//go:build linux

package dockerengine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/moby/moby/client"
)

// VerifyStorageReleased is scoped to the Standard private-namespace template and
// trusted Docker/host administration. It is not the Runnerd09 universal-reference
// retirement proof. Unknown layouts, surviving default cgroups or other container
// bindings block deletion. No host FD scanning is claimed as proof.
func (e *Engine) VerifyStorageReleased(ctx context.Context, id string, p Plan) error {
	if p.StorageDirectory == "" || !filepath.IsAbs(p.StorageDirectory) || filepath.Clean(p.StorageDirectory) != p.StorageDirectory {
		return ErrConflict
	}
	if err := e.check(ctx); err != nil {
		return err
	}
	target := id
	if target == "" {
		target = p.Name
	}
	if _, err := e.Inspect(ctx, target, p); !errors.Is(err, ErrAbsent) {
		return ErrConflict
	}
	info, err := e.api.Info(ctx, client.InfoOptions{})
	if err != nil {
		return e.lost()
	}
	if info.Info.CgroupDriver != "systemd" || info.Info.CgroupVersion != "2" {
		return ErrConflict
	}
	if id != "" {
		if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(id) {
			return ErrConflict
		}
		events, err := os.ReadFile(filepath.Join("/sys/fs/cgroup/system.slice", "docker-"+id+".scope", "cgroup.events"))
		if err == nil {
			if !strings.Contains("\n"+string(events)+"\n", "\npopulated 0\n") {
				return ErrConflict
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return ErrConflict
		}
	}
	list, err := e.api.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		return e.lost()
	}
	if len(list.Items) > 10000 {
		return ErrConflict
	}
	for _, c := range list.Items {
		inspected, err := e.api.ContainerInspect(ctx, c.ID, client.ContainerInspectOptions{})
		if err != nil {
			return e.lost()
		}
		for _, m := range inspected.Container.Mounts {
			if overlapStorage(m.Source, p.StorageDirectory) {
				return ErrConflict
			}
		}
	}
	mounts, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return ErrConflict
	}
	for _, line := range strings.Split(string(mounts), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		unescape := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
		for _, value := range []string{fields[3], fields[4]} {
			if path := unescape.Replace(value); path == p.StorageDirectory || strings.HasPrefix(path, p.StorageDirectory+"/") {
				return ErrConflict
			}
		}
	}
	return e.check(ctx)
}
func overlapStorage(a, b string) bool {
	return a != "" && a != "/" && (a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/"))
}
