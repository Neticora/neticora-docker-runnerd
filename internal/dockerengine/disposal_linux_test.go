//go:build linux

package dockerengine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func TestStorageDisposalRequiresOriginalContainerAbsenceAndContinuity(t *testing.T) {
	e, p, exists, _, _, daemon := fakeEngine(t)
	p.StorageDirectory = filepath.Join(t.TempDir(), "execution")
	ctx := context.Background()
	id := strings.Repeat("c", 64)
	if err := e.VerifyStorageReleased(ctx, id, p); err != nil {
		t.Fatal("absent, unreferenced original rejected", err)
	}
	*exists = true
	if err := e.VerifyStorageReleased(ctx, id, p); !errors.Is(err, ErrConflict) {
		t.Fatal("live reference authorized deletion", err)
	}
	*exists = false
	*daemon = "replacement"
	if err := e.VerifyStorageReleased(ctx, id, p); !errors.Is(err, ErrUnavailable) {
		t.Fatal("replacement daemon authorized disposal", err)
	}
}
func TestOtherContainerBindingAndUnknownCgroupLayoutBlockStorageDisposal(t *testing.T) {
	for _, variant := range []string{"other-container", "unsupported-cgroup"} {
		t.Run(variant, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "execution")
			e, p, _, _, _, _ := fakeEngineWithHook(t, nil, func(w http.ResponseWriter, r *http.Request, path string) bool {
				if variant == "unsupported-cgroup" && path == "/info" {
					json.NewEncoder(w).Encode(map[string]any{"ID": "engine-a", "OSType": "linux", "CgroupDriver": "cgroupfs", "CgroupVersion": "2"})
					return true
				}
				if variant == "other-container" && path == "/containers/json" {
					json.NewEncoder(w).Encode([]map[string]any{{"Id": strings.Repeat("d", 64)}})
					return true
				}
				if variant == "other-container" && strings.Contains(path, strings.Repeat("d", 64)) {
					json.NewEncoder(w).Encode(map[string]any{"Id": strings.Repeat("d", 64), "Mounts": []map[string]any{{"Source": filepath.Join(root, "workspace"), "Destination": "/foreign"}}})
					return true
				}
				return false
			})
			p.StorageDirectory = root
			if err := e.VerifyStorageReleased(context.Background(), strings.Repeat("c", 64), p); !errors.Is(err, ErrConflict) {
				t.Fatal("unretired references accepted", err)
			}
		})
	}
}
