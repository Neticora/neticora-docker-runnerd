// Package stickycache manages only the named LVM thin pool assigned to Runnerd.
package stickycache

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

var ErrVolume = errors.New("sticky cache volume identity or state mismatch")

var lvmName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.+-]{0,62}$`)
var volumeName = regexp.MustCompile(`^nrdc-[0-9a-f]{48}$`)
var ext4UUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type Policy struct {
	VolumeGroup    string `json:"volumeGroup"`
	ThinPool       string `json:"thinPool"`
	PoolUUID       string `json:"poolUuid"`
	VolumeBytes    uint64 `json:"volumeBytes"`
	MaxDataPercent uint8  `json:"maxDataPercent"`
	MaxMetaPercent uint8  `json:"maxMetadataPercent"`
	Retain         int    `json:"retain"`
}

func (p Policy) Valid() bool {
	return lvmName.MatchString(p.VolumeGroup) && lvmName.MatchString(p.ThinPool) &&
		p.PoolUUID != "" && p.VolumeBytes >= 256<<20 && p.VolumeBytes <= 256<<30 && p.VolumeBytes%(4<<20) == 0 &&
		p.MaxDataPercent >= 25 && p.MaxDataPercent <= 85 && p.MaxMetaPercent >= 25 && p.MaxMetaPercent <= 75 &&
		p.Retain >= 1 && p.Retain <= 8
}

type volume struct {
	Name   string `json:"lv_name"`
	UUID   string `json:"lv_uuid"`
	Size   string `json:"lv_size"`
	Active string `json:"lv_active"`
	Open   string `json:"lv_device_open"`
	Tags   string `json:"lv_tags"`
	Pool   string `json:"pool_lv"`
	Type   string `json:"segtype"`
	Data   string `json:"data_percent"`
	Meta   string `json:"metadata_percent"`
}

type LVM struct {
	Policy  Policy
	command func(context.Context, string, ...string) ([]byte, error)
	record  func(Diagnostic)
}

func (l LVM) run(ctx context.Context, binary string, args ...string) ([]byte, error) {
	if l.command != nil {
		return l.command(ctx, binary, args...)
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	paths := map[string]string{"lvs": "/usr/sbin/lvs", "lvcreate": "/usr/sbin/lvcreate", "lvchange": "/usr/sbin/lvchange",
		"lvremove": "/usr/sbin/lvremove", "mkfs.ext4": "/usr/sbin/mkfs.ext4", "blkid": "/usr/sbin/blkid"}
	cmd := exec.CommandContext(ctx, paths[binary], args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	out, err := cmd.Output()
	l.diagnostic(commandDiagnostic(ctx, binary, err))
	return out, err
}

func (l LVM) report(ctx context.Context) ([]volume, error) {
	if !l.Policy.Valid() {
		return nil, ErrVolume
	}
	out, err := l.run(ctx, "lvs", "--reportformat", "json", "--units", "b", "--nosuffix", "-o",
		"lv_name,lv_uuid,lv_size,lv_active,lv_device_open,lv_tags,pool_lv,segtype,data_percent,metadata_percent", l.Policy.VolumeGroup)
	if err != nil {
		return nil, err
	}
	var report struct {
		Report []struct {
			Volumes []volume `json:"lv"`
		}
	}
	if json.Unmarshal(out, &report) != nil || len(report.Report) != 1 {
		return nil, ErrVolume
	}
	return report.Report[0].Volumes, nil
}

func (l LVM) pool(rows []volume) (volume, bool) {
	for _, row := range rows {
		if row.Name == l.Policy.ThinPool {
			return row, row.UUID == l.Policy.PoolUUID && row.Type == "thin-pool"
		}
	}
	return volume{}, false
}

// Headroom reserves the full virtual size per configured slot above measured
// consumption. DataPercent is rounded by LVM, so allow a reporting margin.
func (l LVM) Headroom(ctx context.Context, slots uint64) (bool, error) {
	rows, err := l.report(ctx)
	if err != nil {
		return false, err
	}
	row, ok := l.pool(rows)
	if !ok {
		return false, ErrVolume
	}
	size, e1 := strconv.ParseUint(row.Size, 10, 64)
	data, e2 := strconv.ParseFloat(row.Data, 64)
	meta, e3 := strconv.ParseFloat(row.Meta, 64)
	if size == 0 || slots == 0 || e1 != nil || e2 != nil || e3 != nil || math.IsNaN(data) || math.IsNaN(meta) || data < 0 || meta < 0 {
		l.diagnostic(Diagnostic{Stage: "headroom", Result: "invalid-pool-telemetry"})
		return false, ErrVolume
	}
	reservedPercent := 100 * float64(l.Policy.VolumeBytes) * float64(slots) / float64(size)
	dataAllowed := data+0.01+reservedPercent <= float64(l.Policy.MaxDataPercent)
	metadataAllowed := meta+0.01 < float64(l.Policy.MaxMetaPercent)
	event := Diagnostic{Stage: "headroom", Result: "available", PoolBytes: size, DataPercent: data,
		MetadataPercent: meta, ReservationSlots: slots, VolumeBytes: l.Policy.VolumeBytes,
		ReservationPercent: reservedPercent, MaxDataPercent: l.Policy.MaxDataPercent,
		MaxMetadataPercent: l.Policy.MaxMetaPercent, DataAllowed: dataAllowed, MetadataAllowed: metadataAllowed}
	switch {
	case !dataAllowed && !metadataAllowed:
		event.Result = "data-and-metadata-watermarks"
	case !dataAllowed:
		event.Result = "data-watermark"
	case !metadataAllowed:
		event.Result = "metadata-watermark"
	}
	l.diagnostic(event)
	return dataAllowed && metadataAllowed, nil
}

func (l LVM) owned(rows []volume, name, uuid string) (volume, bool, error) {
	if !volumeName.MatchString(name) {
		return volume{}, false, ErrVolume
	}
	if _, ok := l.pool(rows); !ok {
		return volume{}, false, ErrVolume
	}
	for _, row := range rows {
		if row.Name != name {
			continue
		}
		if row.Type != "thin" || row.Pool != l.Policy.ThinPool ||
			row.Size != strconv.FormatUint(l.Policy.VolumeBytes, 10) ||
			!slices.Contains(strings.Split(row.Tags, ","), "neticora."+name) ||
			row.UUID == "" || (uuid != "" && uuid != row.UUID) {
			return volume{}, false, ErrVolume
		}
		return row, true, nil
	}
	return volume{}, false, nil
}

func (l LVM) path(name string) string {
	return "/dev/" + l.Policy.VolumeGroup + "/" + name
}

// Prepare may retry an intent whose creation response was lost. The caller
// must hold the execution journal and must keep this LV out of Docker until
// the returned UUID and filesystem UUID are durable.
func (l LVM) Prepare(ctx context.Context, name, parentUUID string) (lvUUID, filesystemUUID string, failure error) {
	stage := "snapshot-inventory"
	defer func() {
		result := "ok"
		if failure != nil {
			result = "failed"
		}
		l.diagnostic(Diagnostic{Stage: stage, Result: result, LVUUID: DiagnosticUUID(lvUUID), FilesystemUUID: filesystemUUID})
	}()
	rows, err := l.report(ctx)
	if err != nil {
		return "", "", err
	}
	current, exists, err := l.owned(rows, name, "")
	if err != nil {
		return "", "", err
	}
	target := l.Policy.VolumeGroup + "/" + name
	if !exists {
		args := []string{"--yes", "--name", name, "--addtag", "neticora." + name, "--setactivationskip", "y"}
		if parentUUID == "" {
			args = append(args, "--virtualsize", strconv.FormatUint(l.Policy.VolumeBytes, 10)+"B", "--thinpool", l.Policy.VolumeGroup+"/"+l.Policy.ThinPool)
		} else {
			var parent volume
			for _, row := range rows {
				if row.UUID == parentUUID {
					parent = row
					break
				}
			}
			stage = "snapshot-origin-verification"
			_, present, err := l.owned(rows, parent.Name, parentUUID)
			if err != nil || !present || parent.Active == "active" {
				return "", "", ErrVolume
			}
			// LVM probes the requested segment target during argument validation.
			// Choose thin explicitly so creating a thin snapshot needs no classic dm-snapshot target.
			args = append(args, "--snapshot", "--type", "thin", l.Policy.VolumeGroup+"/"+parent.Name)
		}
		stage = "snapshot-create"
		if _, err = l.run(ctx, "lvcreate", args...); err != nil {
			return "", "", err
		}
		stage = "snapshot-created-volume-verification"
		rows, err = l.report(ctx)
		if err != nil {
			return "", "", err
		}
		current, exists, err = l.owned(rows, name, "")
		if err != nil || !exists {
			return "", "", ErrVolume
		}
	}
	stage = "snapshot-detached-verification"
	if current.Open == "open" {
		return "", "", ErrVolume
	}
	stage = "snapshot-activate"
	if _, err = l.run(ctx, "lvchange", "-ay", "-K", target); err != nil {
		return "", "", err
	}
	if parentUUID == "" {
		stage = "snapshot-format"
		if _, err = l.run(ctx, "mkfs.ext4", "-Fq", "-m", "0", "-E", "nodiscard", l.path(name)); err != nil {
			return "", "", err
		}
	}
	stage = "snapshot-filesystem-uuid"
	raw, err := l.run(ctx, "blkid", "-p", "-s", "UUID", "-o", "value", l.path(name))
	if err != nil || !ext4UUID.Match(bytes.TrimSpace(raw)) {
		return "", "", ErrVolume
	}
	return current.UUID, string(bytes.TrimSpace(raw)), nil
}

func (l LVM) Device(ctx context.Context, name, uuid string) (string, error) {
	rows, err := l.report(ctx)
	if err != nil {
		return "", err
	}
	row, exists, err := l.owned(rows, name, uuid)
	if err != nil || !exists || row.Active != "active" {
		return "", ErrVolume
	}
	path := l.path(name)
	st, err := os.Stat(path)
	if err != nil || st.Mode()&os.ModeDevice == 0 || st.Mode()&os.ModeCharDevice != 0 {
		return "", ErrVolume
	}
	return path, nil
}

// Detach asks device-mapper to close the LV. A live QEMU reference makes
// lvchange fail. Re-observe the exact UUID and activation state before publish.
func (l LVM) Detach(ctx context.Context, name, uuid string) (bool, error) {
	rows, err := l.report(ctx)
	if err != nil {
		return false, err
	}
	row, exists, err := l.owned(rows, name, uuid)
	if err != nil || !exists {
		return false, err
	}
	if row.Active == "active" {
		if _, err := l.run(ctx, "lvchange", "-an", l.Policy.VolumeGroup+"/"+name); err != nil {
			return false, fmt.Errorf("deactivate cache volume: %w", err)
		}
		rows, err = l.report(ctx)
		if err != nil {
			return false, err
		}
		row, exists, err = l.owned(rows, name, uuid)
	}
	if err != nil || !exists || row.Active != "" || row.Open == "open" {
		return false, ErrVolume
	}
	return true, nil
}

func (l LVM) Delete(ctx context.Context, name, uuid string) error {
	present, err := l.Detach(ctx, name, uuid)
	if err != nil || !present {
		return err
	}
	_, err = l.run(ctx, "lvremove", "--yes", l.Policy.VolumeGroup+"/"+name)
	return err
}

// Retained observes a published UUID without activating its filesystem.
func (l LVM) Retained(ctx context.Context, name, uuid string) bool {
	rows, err := l.report(ctx)
	if err != nil {
		l.diagnostic(Diagnostic{Stage: "retained-volume-verification", Result: "inventory-unavailable", LVUUID: DiagnosticUUID(uuid)})
		return false
	}
	row, exists, err := l.owned(rows, name, uuid)
	event := Diagnostic{Stage: "retained-volume-verification", Result: "verified", LVUUID: DiagnosticUUID(uuid)}
	switch {
	case err != nil:
		event.Result = "identity-mismatch"
	case !exists:
		event.Result = "volume-missing"
	case row.Active != "" || row.Open == "open":
		event.Result = "volume-in-use"
	}
	l.diagnostic(event)
	return event.Result == "verified"
}

// VerifyAbsent checks the exact cache LV without adopting or touching it.
func (l LVM) VerifyAbsent(ctx context.Context, name string) error {
	rows, err := l.report(ctx)
	if err != nil {
		return err
	}
	if _, exists, err := l.owned(rows, name, ""); err != nil || exists {
		return ErrVolume
	}
	return nil
}
