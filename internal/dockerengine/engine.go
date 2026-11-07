// Package dockerengine contains Docker mechanics, not provider or admission policy.
package dockerengine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
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
	ErrUnavailable              = errors.New("Docker unavailable or endpoint continuity uncertain")
	ErrConflict                 = errors.New("Docker resource ownership or configuration conflict")
	ErrAbsent                   = errors.New("Docker resource absent")
	ErrStoragePressure          = errors.New("Docker storage headroom unavailable")
	ErrRecoveryApprovalRequired = errors.New("Docker recovery is read-only; scoped operator approval required")
	ErrRecoveryPlan             = errors.New("historical Docker plan cannot prepare images, create or start containers")
)

const LabelPrefix = "com.neticora.runnerd."

// Plan is detached configuration produced by a qualified profile, never raw wire input.
// It deliberately has no bootstrap or environment credential field.
type Plan struct {
	Name       string
	Config     *container.Config
	HostConfig *container.HostConfig
	// RecoveryOnly preserves an old configuration for inspection and teardown
	// without making it eligible for fresh runtime effects.
	RecoveryOnly bool
}

type Object struct {
	StartedAt string `json:"startedAt,omitempty"`
	ID        string
	State     string
	ExitCode  int
	OOMKilled bool
}

// Engine never starts discovered resources, prunes images, creates networks, or
// reads DOCKER_HOST / DOCKER_API_VERSION. Every mutation targets an inspected ID.
type Engine struct {
	readOnly       bool // Immutable for the entire adapter lifetime.
	api            *client.Client
	stream         *client.Client
	socket         string
	installation   string
	mu             sync.Mutex
	socketInfo     os.FileInfo
	daemonID       string
	peer           string
	connectedPeer  string // Pinned on the actual transport connection, never rebound.
	boundEndpoint  string // Operations never follow a replacement engine.
	invalidated    func()
	observePeer    func(context.Context, string) (string, error)
	connectionPeer func(net.Conn) (string, error)
}

func Open(endpoint, installation string, invalidated func()) (*Engine, error) {
	return open(endpoint, installation, invalidated, false)
}

// OpenReadOnly observes a replacement peer without authorizing that peer to
// create/start or mutate resources. It never converts into a normal adapter.
func OpenReadOnly(endpoint, installation string, invalidated func()) (*Engine, error) {
	return open(endpoint, installation, invalidated, true)
}

func open(endpoint, installation string, invalidated func(), readOnly bool) (*Engine, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "unix" || u.Host != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !filepath.IsAbs(u.Path) || filepath.Clean(u.Path) != u.Path || installation == "" {
		return nil, ErrUnavailable
	}
	e := &Engine{socket: u.Path, installation: installation, invalidated: invalidated, readOnly: readOnly}
	api, err := client.New(client.WithHost(endpoint), client.WithDialContext(e.dialContext), client.WithTimeout(15*time.Second), client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, ErrUnavailable
	}
	stream, err := client.New(client.WithHost(endpoint), client.WithDialContext(e.dialContext), client.WithAPIVersionNegotiation())
	if err != nil {
		_ = api.Close()
		return nil, ErrUnavailable
	}
	e.api, e.stream = api, stream
	return e, nil
}

// Authenticate the connection that will carry HTTP bytes. A separate socket
// probe cannot protect the gap before a mutating request opens a new connection.
// An already-connected Unix socket cannot be redirected by replacing its path.
func (e *Engine) dialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", e.socket)
	if err != nil {
		return nil, e.lost()
	}
	reader := e.connectionPeer
	if reader == nil {
		reader = peerIdentityConnection
	}
	peer, err := reader(conn)
	if err != nil || peer == "" {
		_ = conn.Close()
		return nil, e.lost()
	}
	e.mu.Lock()
	if e.connectedPeer == "" {
		e.connectedPeer = peer
	}
	matched := peer == e.connectedPeer
	e.mu.Unlock()
	if !matched {
		_ = conn.Close()
		return nil, e.lost()
	}
	return conn, nil
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
	connected := e.connectedPeer
	changed := e.socketInfo != nil && (!os.SameFile(e.socketInfo, stat) || e.daemonID != info.Info.ID || e.peer != peer)
	e.socketInfo = stat
	e.daemonID = info.Info.ID
	e.peer = peer
	e.mu.Unlock()
	if changed || connected == "" || connected != peer {
		return "", e.lost()
	}
	digest := sha256.Sum256([]byte(e.socket + "\x00" + info.Info.ID + "\x00" + peer))
	endpoint := "docker-" + hex.EncodeToString(digest[:])
	e.mu.Lock()
	if e.boundEndpoint == "" {
		e.boundEndpoint = endpoint
	}
	e.mu.Unlock()
	return endpoint, nil
}

func (e *Engine) check(ctx context.Context) error {
	endpoint, err := e.Probe(ctx)
	if err != nil {
		return err
	}
	e.mu.Lock()
	bound := e.boundEndpoint
	e.mu.Unlock()
	if endpoint != bound {
		return e.lost()
	}
	return nil
}

// CheckHeadroom fences new work only. Cleanup/reporting remain available under
// pressure. This does not establish aggregate hard storage isolation.
func (e *Engine) CheckHeadroom(ctx context.Context, minimum uint64) error {
	if err := e.check(ctx); err != nil {
		return err
	}
	info, err := e.api.Info(ctx, client.InfoOptions{})
	if err != nil {
		return e.lost()
	}
	root := info.Info.DockerRootDir
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || minimum == 0 {
		return ErrStoragePressure
	}
	available, err := storageAvailable(root)
	if err != nil || available < minimum {
		return ErrStoragePressure
	}
	return e.check(ctx)
}

// PrepareImage pulls only the immutable verified reference. It never obtains
// authority/JIT or starts a container. Registry credentials are not inherited.
func (e *Engine) PrepareImage(ctx context.Context, p Plan) error {
	if p.RecoveryOnly {
		return ErrRecoveryPlan
	}
	if e.readOnly {
		return ErrRecoveryApprovalRequired
	}
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
	if i.Config == nil || len(i.Config.Volumes) != 0 || p.Config.Labels[LabelPrefix+"template"] == "" || i.Config.Labels[LabelPrefix+"template"] != p.Config.Labels[LabelPrefix+"template"] || i.Config.Labels[LabelPrefix+"docker-build"] != p.Config.Labels[LabelPrefix+"docker-build"] || i.Config.Labels[LabelPrefix+"hard-storage-limit"] != p.Config.Labels[LabelPrefix+"hard-storage-limit"] {
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
			if err := e.check(ctx); err != nil {
				return Object{}, err
			}
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
	if !reflect.DeepEqual(h.StorageOpt, want.StorageOpt) || !reflect.DeepEqual(h.Annotations, want.Annotations) || c.RestartCount != 0 {
		return Object{}, ErrConflict
	}
	if h.CgroupParent != want.CgroupParent || (want.Runtime != "" && h.Runtime != want.Runtime) || (want.CgroupnsMode != "" && h.CgroupnsMode != want.CgroupnsMode) || h.PublishAllPorts || len(h.GroupAdd) != 0 || len(h.Links) != 0 || h.UsernsMode != want.UsernsMode {
		return Object{}, ErrConflict
	}
	if h.Privileged || h.AutoRemove || h.RestartPolicy.Name != "no" || h.NetworkMode != want.NetworkMode || h.PidMode != "" || h.IpcMode != "private" || h.UTSMode != "" || !reflect.DeepEqual(h.CapAdd, want.CapAdd) || !reflect.DeepEqual(h.CapDrop, want.CapDrop) || !reflect.DeepEqual(h.SecurityOpt, want.SecurityOpt) || !slices.Equal(h.Devices, want.Devices) || len(h.DeviceRequests) != 0 || len(h.VolumesFrom) != 0 || len(h.Binds) != 0 || len(h.PortBindings) != 0 || h.ReadonlyRootfs != want.ReadonlyRootfs || !resourceMatch(h.Resources, want.Resources) || !reflect.DeepEqual(h.Mounts, want.Mounts) || !reflect.DeepEqual(h.Tmpfs, want.Tmpfs) || !reflect.DeepEqual(h.LogConfig, want.LogConfig) {
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
	if err := e.check(ctx); err != nil {
		return Object{}, err
	}
	object := Object{ID: c.ID, State: state, ExitCode: c.State.ExitCode, OOMKilled: c.State.OOMKilled}
	if p.Config.Labels[LabelPrefix+"template"] == "linux-github-kata-v1" || p.Config.Labels[LabelPrefix+"template"] == "linux-github-kata-v2" {
		object.StartedAt = c.State.StartedAt
	}
	return object, nil
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
	if p.RecoveryOnly {
		return Object{}, ErrRecoveryPlan
	}
	if e.readOnly {
		return Object{}, ErrRecoveryApprovalRequired
	}
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
	if err = e.check(ctx); err != nil {
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
	if p.RecoveryOnly {
		return Object{}, ErrRecoveryPlan
	}
	if e.readOnly {
		return Object{}, ErrRecoveryApprovalRequired
	}
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
	if err = e.check(ctx); err != nil {
		return Object{}, err
	}
	if _, err = e.api.ContainerStart(ctx, id, client.ContainerStartOptions{}); err != nil {
		return Object{}, e.lost()
	}
	return e.Inspect(ctx, id, p)
}

func (e *Engine) Stop(ctx context.Context, id string, p Plan) error {
	if e.readOnly {
		return ErrRecoveryApprovalRequired
	}
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
	if e.readOnly {
		return ErrRecoveryApprovalRequired
	}
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
