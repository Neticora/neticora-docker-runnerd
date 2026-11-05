// Package dockerengine contains Docker mechanics, not provider or admission policy.
package dockerengine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/containerd/errdefs"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

var (
	ErrUnavailable = errors.New("Docker unavailable or endpoint continuity uncertain")
	ErrConflict    = errors.New("Docker resource ownership or configuration conflict")
	ErrAbsent      = errors.New("Docker resource absent")
)

const LabelPrefix = "com.neticora.runnerd."

// Plan is detached configuration produced by a qualified profile, never raw wire input.
// It deliberately has no bootstrap or environment credential field.
type Plan struct {
	Name       string
	Config     *container.Config
	HostConfig *container.HostConfig
}

type Object struct {
	ID        string
	State     string
	ExitCode  int
	OOMKilled bool
}

// Engine never starts discovered resources, prunes images, creates networks, or
// reads DOCKER_HOST / DOCKER_API_VERSION. Every mutation targets an inspected ID.
type Engine struct {
	api          *client.Client
	stream       *client.Client
	socket       string
	installation string
	mu           sync.Mutex
	socketInfo   os.FileInfo
	daemonID     string
	peer         string
	invalidated  func()
	observePeer  func(context.Context, string) (string, error)
}

func Open(endpoint, installation string, invalidated func()) (*Engine, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "unix" || u.Host != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !filepath.IsAbs(u.Path) || filepath.Clean(u.Path) != u.Path || installation == "" {
		return nil, ErrUnavailable
	}
	api, err := client.New(client.WithHost(endpoint), client.WithTimeout(15*time.Second), client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, ErrUnavailable
	}
	stream, err := client.New(client.WithHost(endpoint), client.WithAPIVersionNegotiation())
	if err != nil {
		_ = api.Close()
		return nil, ErrUnavailable
	}
	return &Engine{api: api, stream: stream, socket: u.Path, installation: installation, invalidated: invalidated}, nil
}

func (e *Engine) Close() error { return errors.Join(e.api.Close(), e.stream.Close()) }

func (e *Engine) lost() error {
	if e.invalidated != nil {
		e.invalidated()
	}
	return ErrUnavailable
}

// Probe records continuity signals, not a universally stable daemon boot ID.
// A disconnect/event-stream loss must independently invalidate reconciliation.
func (e *Engine) Probe(ctx context.Context) (string, error) {
	stat, err := os.Lstat(e.socket)
	if err != nil || stat.Mode()&os.ModeSocket == 0 {
		return "", e.lost()
	}
	info, err := e.api.Info(ctx, client.InfoOptions{})
	if err != nil || info.Info.OSType != "linux" || info.Info.ID == "" {
		return "", e.lost()
	}
	reader := e.observePeer
	if reader == nil {
		reader = peerIdentity
	}
	peer, err := reader(ctx, e.socket)
	if err != nil {
		return "", e.lost()
	}
	e.mu.Lock()
	changed := e.socketInfo != nil && (!os.SameFile(e.socketInfo, stat) || e.daemonID != info.Info.ID || e.peer != peer)
	e.socketInfo = stat
	e.daemonID = info.Info.ID
	e.peer = peer
	e.mu.Unlock()
	if changed {
		return "", e.lost()
	}
	digest := sha256.Sum256([]byte(e.socket + "\x00" + info.Info.ID + "\x00" + peer))
	return "docker-" + hex.EncodeToString(digest[:]), nil
}

func (e *Engine) check(ctx context.Context) error { _, err := e.Probe(ctx); return err }

// PrepareImage pulls only the immutable verified reference. It never obtains
// authority/JIT or starts a container. Registry credentials are not inherited.
func (e *Engine) PrepareImage(ctx context.Context, p Plan) error {
	if err := e.check(ctx); err != nil {
		return err
	}
	if p.Config == nil || !strings.Contains(p.Config.Image, "@sha256:") {
		return ErrConflict
	}
	network, err := e.api.NetworkInspect(ctx, string(p.HostConfig.NetworkMode), client.NetworkInspectOptions{})
	if err != nil || network.Network.ID != string(p.HostConfig.NetworkMode) || network.Network.Driver != "bridge" || network.Network.Scope != "local" {
		return ErrConflict
	}
	i, err := e.api.ImageInspect(ctx, p.Config.Image)
	if err != nil && errdefs.IsNotFound(err) {
		pullCtx, stop := context.WithTimeout(ctx, 5*time.Minute)
		defer stop()
		pull, e2 := e.stream.ImagePull(pullCtx, p.Config.Image, client.ImagePullOptions{})
		if e2 != nil {
			return e.lost()
		}
		err = pull.Wait(pullCtx)
		_ = pull.Close()
		if err != nil {
			return e.lost()
		}
		i, err = e.api.ImageInspect(ctx, p.Config.Image)
	}
	if err != nil {
		return e.lost()
	}
	if i.Os != "linux" || i.Architecture != "amd64" || !slices.Contains(i.RepoDigests, p.Config.Image) {
		return ErrConflict
	}
	if i.Config == nil || len(i.Config.Volumes) != 0 || i.Config.Labels[LabelPrefix+"template"] != "linux-github-process-v1" || i.Config.Labels[LabelPrefix+"docker-build"] != "false" {
		return ErrConflict
	}
	for _, v := range i.Config.Env {
		if strings.HasPrefix(v, "DOCKER_HOST=") || strings.HasPrefix(v, "ACTIONS_RUNNER_INPUT_JITCONFIG=") || strings.HasPrefix(v, "RUNNER_TOKEN=") {
			return ErrConflict
		}
	}
	return e.check(ctx)
}

// Inventory is complete only if the endpoint remains bound throughout listing.
// Labels select candidates; the controller must match each against durable specs.
func (e *Engine) Inventory(ctx context.Context) ([]string, error) {
	if err := e.check(ctx); err != nil {
		return nil, err
	}
	result, err := e.api.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("label", LabelPrefix+"installation="+e.installation)})
	if err != nil {
		return nil, e.lost()
	}
	if len(result.Items) > 1000 {
		return nil, ErrConflict
	}
	ids := make([]string, 0, len(result.Items))
	for _, item := range result.Items {
		ids = append(ids, item.ID)
	}
	if err = e.check(ctx); err != nil {
		return nil, err
	}
	return ids, nil
}

// Inspect checks immutable ownership AND actual security/resource settings. Names
// and execution labels alone never establish authority to adopt, start or remove.
func (e *Engine) Inspect(ctx context.Context, id string, p Plan) (Object, error) {
	if err := e.check(ctx); err != nil {
		return Object{}, err
	}
	r, err := e.api.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if err != nil {
		if errdefs.IsNotFound(err) {
			return Object{}, ErrAbsent
		}
		return Object{}, e.lost()
	}
	c := r.Container
	if c.Config == nil || c.HostConfig == nil || c.State == nil || c.ID == "" || p.Config == nil || p.HostConfig == nil {
		return Object{}, ErrConflict
	}
	if c.Config.Image != p.Config.Image || c.Config.User != p.Config.User || !labelsMatch(c.Config.Labels, p.Config.Labels) || !reflect.DeepEqual([]string(c.Config.Entrypoint), []string(p.Config.Entrypoint)) || !reflect.DeepEqual([]string(c.Config.Cmd), []string(p.Config.Cmd)) || c.Config.WorkingDir != p.Config.WorkingDir || c.Config.Tty || c.Config.OpenStdin {
		return Object{}, ErrConflict
	}
	// Image-defined ENV is part of the independently verified image. Runtime ENV
	image, err := e.api.ImageInspect(ctx, p.Config.Image)
	if err != nil {
		return Object{}, e.lost()
	}
	if image.Config == nil || c.Image != image.ID || !reflect.DeepEqual(c.Config.Env, image.Config.Env) {
		return Object{}, ErrConflict
	}
	// overrides are forbidden by the Standard profile; inspection rejects secrets.
	for _, env := range c.Config.Env {
		if strings.HasPrefix(env, "ACTIONS_RUNNER_INPUT_JITCONFIG=") || strings.HasPrefix(env, "RUNNER_TOKEN=") || strings.HasPrefix(env, "DOCKER_HOST=") {
			return Object{}, ErrConflict
		}
	}
	h, want := c.HostConfig, p.HostConfig
	if (want.Runtime != "" && h.Runtime != want.Runtime) || (want.CgroupnsMode != "" && h.CgroupnsMode != want.CgroupnsMode) || h.PublishAllPorts || len(h.GroupAdd) != 0 || len(h.Links) != 0 || h.UsernsMode != want.UsernsMode {
		return Object{}, ErrConflict
	}
	if h.Privileged || h.AutoRemove || h.RestartPolicy.Name != "no" || h.NetworkMode != want.NetworkMode || h.PidMode != "" || h.IpcMode != "private" || h.UTSMode != "" || len(h.CapAdd) != 0 || !reflect.DeepEqual(h.CapDrop, want.CapDrop) || !reflect.DeepEqual(h.SecurityOpt, want.SecurityOpt) || len(h.Devices) != 0 || len(h.DeviceRequests) != 0 || len(h.VolumesFrom) != 0 || len(h.Binds) != 0 || len(h.PortBindings) != 0 || h.ReadonlyRootfs != want.ReadonlyRootfs || !resourceMatch(h.Resources, want.Resources) || !reflect.DeepEqual(h.Mounts, want.Mounts) || !reflect.DeepEqual(h.Tmpfs, want.Tmpfs) || !reflect.DeepEqual(h.LogConfig, want.LogConfig) {
		return Object{}, ErrConflict
	}
	state := "unknown"
	switch {
	case c.State.Running:
		state = "running"
	case c.State.Status == "created":
		state = "prepared"
	case c.State.Status == "exited" || c.State.Status == "dead":
		state = "exited"
	}
	return Object{ID: c.ID, State: state, ExitCode: c.State.ExitCode, OOMKilled: c.State.OOMKilled}, nil
}

func resourceMatch(actual, want container.Resources) bool {
	// Docker normalizes an omitted OomKillDisable into an explicit false pointer.
	// Disabling the OOM killer is never an equivalent or accepted default.
	if actual.OomKillDisable != nil && *actual.OomKillDisable {
		return false
	}
	if want.OomKillDisable != nil && *want.OomKillDisable {
		return false
	}
	actual.OomKillDisable = nil
	want.OomKillDisable = nil
	return reflect.DeepEqual(actual, want)
}

// Ensure creates at most once only after the caller durably crosses its creation
// fence. A lost create response returns uncertainty; it never retries creation.
func (e *Engine) Ensure(ctx context.Context, p Plan, claim func() error) (Object, error) {
	if p.Config == nil || p.Config.Labels[LabelPrefix+"installation"] != e.installation || p.Name == "" {
		return Object{}, ErrConflict
	}
	existing, err := e.Inspect(ctx, p.Name, p)
	if err == nil {
		return existing, nil
	}
	if !errors.Is(err, ErrAbsent) {
		return Object{}, err
	}
	if err = e.check(ctx); err != nil {
		return Object{}, err
	}
	if claim == nil {
		return Object{}, ErrConflict
	}
	if err = claim(); err != nil {
		return Object{}, err
	}
	r, err := e.api.ContainerCreate(ctx, client.ContainerCreateOptions{Name: p.Name, Config: p.Config, HostConfig: p.HostConfig})
	if err != nil {
		return Object{}, e.lost()
	}
	return e.Inspect(ctx, r.ID, p)
}

func labelsMatch(actual, want map[string]string) bool {
	for k, v := range want {
		if actual[k] != v {
			return false
		}
	}
	for k := range actual {
		if strings.HasPrefix(k, LabelPrefix) {
			if _, ok := want[k]; !ok {
				return false
			}
		}
	}
	return true
}

func (e *Engine) Start(ctx context.Context, id string, p Plan, authorize func() error) (Object, error) {
	o, err := e.Inspect(ctx, id, p)
	if err != nil {
		return o, err
	}
	if o.State == "running" {
		return o, nil
	}
	if o.State != "prepared" || authorize == nil {
		return Object{}, ErrConflict
	}
	if err = authorize(); err != nil {
		return Object{}, err
	}
	if _, err = e.api.ContainerStart(ctx, id, client.ContainerStartOptions{}); err != nil {
		return Object{}, e.lost()
	}
	return e.Inspect(ctx, id, p)
}

func (e *Engine) Stop(ctx context.Context, id string, p Plan) error {
	o, err := e.Inspect(ctx, id, p)
	if errors.Is(err, ErrAbsent) {
		return nil
	}
	if err != nil {
		return err
	}
	if o.State != "running" {
		return nil
	}
	seconds := 10
	if _, err = e.api.ContainerStop(ctx, id, client.ContainerStopOptions{Timeout: &seconds}); err != nil {
		return e.lost()
	}
	return nil
}
func (e *Engine) Remove(ctx context.Context, id string, p Plan) error {
	o, err := e.Inspect(ctx, id, p)
	if errors.Is(err, ErrAbsent) {
		return nil
	}
	if err != nil {
		return err
	}
	if o.State == "running" {
		return ErrConflict
	}
	if _, err = e.api.ContainerRemove(ctx, id, client.ContainerRemoveOptions{}); err != nil {
		return e.lost()
	}
	return nil
}

// Watch signals prompt repair; periodic Inventory remains authoritative. Stream
// closure/disconnect invalidates continuity even when the socket and ID match.
func (e *Engine) Watch(ctx context.Context, trigger func()) error {
	stream := e.stream.Events(ctx, client.EventsListOptions{Filters: client.Filters{}.Add("type", "container").Add("label", LabelPrefix+"installation="+e.installation)})
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case _, ok := <-stream.Messages:
			if !ok {
				return e.lost()
			}
			trigger()
		case <-stream.Err:
			return e.lost()
		}
	}
}
