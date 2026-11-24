package stickycache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func testPolicy() Policy {
	return Policy{VolumeGroup: "nrdphase1", ThinPool: "cache", PoolUUID: "pool-uuid",
		VolumeBytes: 3 << 30, MaxDataPercent: 75, MaxMetaPercent: 60, Retain: 2}
}

func TestHeadroomChecksBothThresholdsAndAllSlots(t *testing.T) {
	policy := testPolicy()
	for _, item := range []struct {
		data, meta string
		want       bool
	}{{"0.00", "1.59", true}, {"65.00", "1.59", false}, {"0.00", "61.00", false}} {
		lvm := LVM{Policy: policy, command: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
			return []byte(fmt.Sprintf(`{"report":[{"lv":[{"lv_name":"cache","lv_uuid":"pool-uuid","segtype":"thin-pool","lv_size":"42949672960","data_percent":"%s","metadata_percent":"%s"}]}]}`, item.data, item.meta)), nil
		}}
		got, err := lvm.Headroom(t.Context(), 2)
		if err != nil || got != item.want {
			t.Fatalf("data %s metadata %s: %t, %v", item.data, item.meta, got, err)
		}
	}
}

func TestDetachRefusesWrongUUIDAndBusyVolume(t *testing.T) {
	name := "nrdc-" + strings.Repeat("c", 48)
	mutated := 0
	lvm := LVM{Policy: testPolicy(), command: func(_ context.Context, tool string, _ ...string) ([]byte, error) {
		if tool == "lvs" {
			return []byte(fmt.Sprintf(`{"report":[{"lv":[{"lv_name":"cache","lv_uuid":"pool-uuid","segtype":"thin-pool"},{"lv_name":"%s","lv_uuid":"actual","pool_lv":"cache","segtype":"thin","lv_size":"3221225472","lv_active":"active","lv_device_open":"open","lv_tags":"neticora.%s"}]}]}`, name, name)), nil
		}
		mutated++
		return nil, errors.New("device is in use")
	}}
	if _, err := lvm.Detach(t.Context(), name, "substitution"); !errors.Is(err, ErrVolume) || mutated != 0 {
		t.Fatalf("wrong LV mutated: %v, count %d", err, mutated)
	}
	if _, err := lvm.Detach(t.Context(), name, "actual"); err == nil || mutated != 1 {
		t.Fatalf("busy LV detached: %v, count %d", err, mutated)
	}
}

func TestNativeThinCache(t *testing.T) {
	pool := os.Getenv("NETICORA_PHASE2_LAB_THIN_UUID")
	if pool == "" {
		t.Skip("requires dedicated runnerd-kata lab")
	}
	host, err := os.Hostname()
	if err != nil || host != "neticora-runnerd-kata" || os.Geteuid() != 0 {
		t.Fatal("dedicated runnerd-kata lab root required")
	}
	policy := testPolicy()
	policy.PoolUUID = pool
	lvm := LVM{Policy: policy}
	ctx := t.Context()
	if ok, err := lvm.Headroom(ctx, 2); err != nil || !ok {
		t.Fatalf("headroom: %v %v", ok, err)
	}
	prefix := fmt.Sprintf("nrdc-%047x", time.Now().UnixNano())
	prepare := func(name, parent string) (string, string) {
		t.Helper()
		t.Cleanup(func() {
			if err := lvm.Delete(context.Background(), name, ""); err != nil {
				t.Error(err)
			}
		})
		id, fs, err := lvm.Prepare(ctx, name, parent)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := lvm.Device(ctx, name, id); err != nil {
			t.Fatal(err)
		}
		return id, fs
	}
	seed := prefix + "0"
	origin, filesystem := prepare(seed, "")
	if ok, err := lvm.Detach(ctx, seed, origin); err != nil || !ok {
		t.Fatalf("origin detach: %v %v", ok, err)
	}
	left, leftFS := prepare(prefix+"1", origin)
	right, rightFS := prepare(prefix+"2", origin)
	if left == right || left == origin || right == origin || leftFS != filesystem || rightFS != filesystem {
		t.Fatal("thin clone identity mismatch")
	}
	t.Logf("independent active children %s and %s share ext4 filesystem UUID %s with inactive origin %s", left, right, filesystem, origin)
	for i, id := range []string{left, right} {
		name := fmt.Sprintf("%s%d", prefix, i+1)
		if ok, err := lvm.Detach(ctx, name, id); err != nil || !ok || !lvm.Retained(ctx, name, id) {
			t.Fatalf("child detach: %v %v", ok, err)
		}
	}
}

// TestNativeThinCacheReboot is run in two test processes on the dedicated VM,
// with an actual reboot between the prepared and recovered states.
func TestNativeThinCacheReboot(t *testing.T) {
	pool := os.Getenv("NETICORA_PHASE2_LAB_THIN_UUID")
	phase := os.Getenv("NETICORA_PHASE2_LAB_REBOOT")
	if pool == "" || phase == "" {
		t.Skip("requires dedicated runnerd-kata reboot campaign")
	}
	if host, err := os.Hostname(); err != nil || host != "neticora-runnerd-kata" || os.Geteuid() != 0 {
		t.Fatal("dedicated runnerd-kata lab root required")
	}
	policy := testPolicy()
	policy.PoolUUID = pool
	lvm := LVM{Policy: policy}
	ctx := t.Context()
	const statePath = "/var/tmp/neticora-phase2-stickydisk-reboot.json"
	type rebootState struct{ Boot, Name, UUID, Filesystem string }
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	if phase == "prepare" {
		stateFile, err := os.OpenFile(statePath, os.O_WRONLY|os.O_EXCL|os.O_CREATE, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer stateFile.Close()
		name := fmt.Sprintf("nrdc-%048x", time.Now().UnixNano())
		uuid, fs, err := lvm.Prepare(ctx, name, "")
		if err != nil {
			t.Fatal(err)
		}
		if ok, err := lvm.Detach(ctx, name, uuid); !ok || err != nil {
			t.Fatalf("detach before reboot: %v %v", ok, err)
		}
		state := rebootState{strings.TrimSpace(string(boot)), name, uuid, fs}
		if err := json.NewEncoder(stateFile).Encode(state); err != nil {
			t.Fatal(err)
		}
		if err := stateFile.Sync(); err != nil {
			t.Fatal(err)
		}
		t.Logf("persisted inactive head %s on boot %s", uuid, state.Boot)
		return
	}
	if phase != "recover" {
		t.Fatalf("bad reboot test phase %q", phase)
	}
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var state rebootState
	if err = json.Unmarshal(raw, &state); err != nil || !volumeName.MatchString(state.Name) || state.UUID == "" {
		t.Fatal("invalid exact recovery record")
	}
	if state.Boot == strings.TrimSpace(string(boot)) || !lvm.Retained(ctx, state.Name, state.UUID) {
		t.Fatal("new boot or retained head missing")
	}
	child := fmt.Sprintf("nrdc-%048x", time.Now().UnixNano())
	t.Cleanup(func() {
		if err := lvm.Delete(context.Background(), child, ""); err != nil {
			t.Error(err)
		}
		if err := lvm.Delete(context.Background(), state.Name, state.UUID); err != nil {
			t.Error(err)
		}
		if err := os.Remove(statePath); err != nil {
			t.Error(err)
		}
	})
	uuid, fs, err := lvm.Prepare(ctx, child, state.UUID)
	if err != nil || uuid == state.UUID || fs != state.Filesystem {
		t.Fatalf("failed to clone retained filesystem: %q %q %v", uuid, fs, err)
	}
	t.Logf("restored retained %s and prepared child %s on boot %s", state.UUID, uuid, strings.TrimSpace(string(boot)))
}

// TestNativeThinCachePressure reads the real isolated pool while both
// disposable workload LVs are active. The lab owns allocation and cleanup.
func TestNativeThinCachePressure(t *testing.T) {
	pool := os.Getenv("NETICORA_PHASE2B_PRESSURE_UUID")
	phase := os.Getenv("NETICORA_PHASE2B_PRESSURE_PHASE")
	if pool == "" || phase == "" {
		t.Skip("requires dedicated runnerd-kata pressure pool")
	}
	if host, err := os.Hostname(); err != nil || host != "neticora-runnerd-kata" || os.Geteuid() != 0 {
		t.Fatal("dedicated runnerd-kata lab root required")
	}
	policy := testPolicy()
	policy.ThinPool = "phase2bpressure"
	policy.PoolUUID = pool
	policy.VolumeBytes = 256 << 20
	policy.MaxMetaPercent = 75
	lvm := LVM{Policy: policy}
	rows, err := lvm.report(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	row, ok := lvm.pool(rows)
	if !ok {
		t.Fatal("pressure pool identity mismatch")
	}
	var active int
	for _, candidate := range rows {
		if candidate.Pool == policy.ThinPool && candidate.Type == "thin" && candidate.Active == "active" {
			active++
		}
	}
	if active != 2 {
		t.Fatalf("expected both active test disks, got %d", active)
	}
	if phase == "metadata" {
		otherwiseAllowed, err := lvm.Headroom(t.Context(), uint64(active))
		if err != nil || !otherwiseAllowed {
			t.Fatalf("metadata probe must preserve data headroom: %t %v", otherwiseAllowed, err)
		}
		lvm.Policy.MaxMetaPercent = 25
	}
	admitted, err := lvm.Headroom(t.Context(), uint64(active))
	if err != nil || admitted != (phase == "baseline") {
		t.Fatalf("%s data=%s%% metadata=%s%% admission=%t error=%v", phase, row.Data, row.Meta, admitted, err)
	}
	t.Logf("%s active_slots=%d data=%s%% metadata=%s%% sticky_allowed=%t", phase, active, row.Data, row.Meta, admitted)
}
