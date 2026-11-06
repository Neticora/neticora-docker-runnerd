//go:build linux && runnerd_docker

package dockerengine

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
)

// This explicit root lab test fills only a separately mounted bounded volume.
// It tests soft headroom and owned cleanup, never a hard per-job storage quota.
func TestRunnerd08AggregateStoragePressure(t *testing.T) {
	root := os.Getenv("RUNNERD08_AGGREGATE_ROOT")
	if root == "" {
		t.Skip("separate bounded Docker filesystem required")
	}
	if os.Geteuid() != 0 || !strings.HasPrefix(root, "/var/tmp/runnerd08-aggregate-") || filepath.Clean(root) != root {
		t.Fatal("explicit root lab required")
	}
	if _, err := os.Stat("/etc/neticora-runnerd-lab"); err != nil {
		t.Fatal(err)
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs(root, &fs); err != nil || uint64(fs.Blocks)*uint64(fs.Bsize) > 10<<30 || fs.Type != 0xef53 {
		t.Fatal("bounded ext4 fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	e, err := Open("unix:///run/runnerd08-aggregate.sock", "runnerd08-aggregate", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	info, err := e.api.Info(ctx, client.InfoOptions{})
	if err != nil || info.Info.DockerRootDir != filepath.Join(root, "docker") {
		t.Fatal("isolated Docker data root required")
	}
	image := os.Getenv("RUNNERD08_AGGREGATE_IMAGE")
	if !strings.Contains(image, "@sha256:") && !(strings.HasPrefix(image, "sha256:") && len(image) == 71) {
		t.Fatal("immutable image required")
	}
	img, err := e.api.ImageInspect(ctx, image)
	if err != nil || img.Config == nil {
		t.Fatal("image unavailable", err)
	}
	workspace := filepath.Join(root, "workspace")
	if err = os.Mkdir(workspace, 0777); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(workspace, 0777); err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{}
	for k, v := range img.Config.Labels {
		labels[k] = v
	}
	labels[LabelPrefix+"installation"] = "runnerd08-aggregate"
	pids := int64(128)
	p := Plan{Name: "nrd-runnerd08-aggregate", Config: &container.Config{Image: image, User: "10001:10001", WorkingDir: "/tmp", Entrypoint: []string{"/usr/bin/python3"}, Cmd: []string{"-c", "import os,time; b=b'x'*(1<<20); f=open('/workspace/probe','wb'); g=open('/tmp/layer-probe','wb'); [(f.write(b),g.write(b)) for _ in range(128)]; f.flush();g.flush();os.fsync(f.fileno());os.fsync(g.fileno()); [os.write(1,b) for _ in range(16)]; open('/workspace/ready','w').write('ready'); time.sleep(240)"}, Labels: labels}, HostConfig: &container.HostConfig{RestartPolicy: container.RestartPolicy{Name: "no"}, NetworkMode: "none", IpcMode: "private", CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges=true"}, Mounts: []mount.Mount{{Type: mount.TypeBind, Source: workspace, Target: "/workspace"}}, Resources: container.Resources{Memory: 256 << 20, MemorySwap: 256 << 20, PidsLimit: &pids}, LogConfig: container.LogConfig{Type: "local", Config: map[string]string{"max-size": "1m", "max-file": "2"}}}}
	p.Config.User = "982:982"
	p.HostConfig.Resources.Memory = 2 << 30
	p.HostConfig.Resources.MemorySwap = 2 << 30
	if err = e.CheckHeadroom(ctx, 256<<20); err != nil {
		t.Fatal("baseline headroom", err)
	}
	o, err := e.Ensure(ctx, p, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.Start(ctx, o.ID, p, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	for {
		if _, err = os.Stat(filepath.Join(workspace, "ready")); err == nil {
			break
		}
		observed, err := e.Inspect(ctx, o.ID, p)
		if err != nil || observed.State == "exited" {
			t.Fatal("synthetic writer exited before pressure phase", observed, err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("container writes deadline")
		case <-time.After(100 * time.Millisecond):
		}
	}
	filler := filepath.Join(root, "unrelated-fill")
	f, err := os.OpenFile(filler, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	block := make([]byte, 1<<20)
	for {
		available, err := storageAvailable(root)
		if err != nil {
			t.Fatal(err)
		}
		if available < 32<<20 {
			break
		}
		if _, err = f.Write(block); err != nil {
			t.Fatal(err)
		}
	}
	if err = f.Sync(); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if err = e.CheckHeadroom(ctx, 256<<20); !errors.Is(err, ErrStoragePressure) {
		t.Fatal("combined consumption did not fence new work", err)
	}
	// Cleanup is deliberately exercised under the same low-space condition.
	if err = e.Stop(ctx, o.ID, p); err != nil {
		t.Fatal("pressure blocked stop", err)
	}
	if err = e.Remove(ctx, o.ID, p); err != nil {
		t.Fatal("pressure blocked owned removal", err)
	}
	if _, err = e.Inspect(ctx, o.ID, p); !errors.Is(err, ErrAbsent) {
		t.Fatal("owned absence unverified", err)
	}
	// Exhaust the same aggregate filesystem after verified owned cleanup. The
	// separate journal ENOSPC suite covers retained obligations on failed writes.
	f, err = os.OpenFile(filler, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	for {
		_, err = f.Write(block)
		if err != nil {
			break
		}
	}
	_ = f.Close()
	if !errors.Is(err, syscall.ENOSPC) {
		t.Fatal("aggregate ENOSPC not observed", err)
	}
	if err = e.CheckHeadroom(ctx, 256<<20); !errors.Is(err, ErrStoragePressure) {
		t.Fatal("exhausted aggregate filesystem admitted work", err)
	}
	if err = os.Remove(filler); err != nil {
		t.Fatal(err)
	}
	if err = e.CheckHeadroom(ctx, 256<<20); err != nil {
		t.Fatal("headroom did not recover", err)
	}
	report, _ := json.Marshal(map[string]any{"result": "pass", "softStorage": true, "workspaceBytes": 128 << 20, "writableLayerBytes": 128 << 20, "stdoutBytes": 16 << 20, "logRotation": "1MiB x 2", "unrelatedWrites": true, "newWorkFenced": true, "cleanupUnderPressure": true, "ownedAbsenceVerified": true, "headroomRecovered": true, "dockerVersion": info.Info.ServerVersion, "storageDriver": info.Info.Driver})
	t.Log("aggregate_enospc_verified=true " + string(report))
}
