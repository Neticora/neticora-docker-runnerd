//go:build linux

package dockerengine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"golang.org/x/sys/unix"
)

func matchingKataStartupConfig(raw []byte, selector, shim, config string) bool {
	if _, err := protocol.CanonicalizeJSON(raw); err != nil {
		return false
	}
	var daemon map[string]json.RawMessage
	if json.Unmarshal(raw, &daemon) != nil {
		return false
	}
	var runtimes map[string]json.RawMessage
	if json.Unmarshal(daemon["runtimes"], &runtimes) != nil {
		return false
	}
	var selected struct {
		Type    string            `json:"runtimeType"`
		Options map[string]string `json:"options"`
	}
	decoder := json.NewDecoder(bytes.NewReader(runtimes[selector]))
	decoder.DisallowUnknownFields()
	return decoder.Decode(&selected) == nil && selected.Type == shim && len(selected.Options) == 1 && selected.Options["ConfigPath"] == config
}
func exactDaemonConfigArgument(args []string, config string) bool {
	return (len(args) == 3 && args[1] == "--config-file" && args[2] == config) ||
		(len(args) == 2 && args[1] == "--config-file="+config)
}

// Docker may omit runtimeType/options from /info. Do not turn key presence into
// authority: require the signed full config hash and exact bound dockerd's
// startup argument instead. Config changes after startup, including restoring
// old bytes after a reload, require a restart and requalification.
func (e *Engine) verifyKataStartupConfig(ctx context.Context, selector, shim, config, file, expected string) error {
	if runtime.GOARCH != "amd64" || len(expected) != 64 || !filepath.IsAbs(file) || filepath.Clean(file) != file || hostfs.CheckAncestors(filepath.Dir(file)) != nil {
		return ErrConflict
	}
	e.mu.Lock()
	peer := e.connectedPeer
	e.mu.Unlock()
	fields := strings.Split(peer, ":")
	if len(fields) != 3 {
		return ErrConflict
	}
	pid, err := strconv.ParseUint(fields[1], 10, 31)
	if err != nil || pid <= 1 {
		return ErrConflict
	}
	ticks, err := strconv.ParseUint(fields[2], 10, 64)
	if err != nil || ticks > uint64(^uint64(0)>>1)/10_000_000 {
		return ErrConflict
	}
	args, err := os.ReadFile("/proc/" + fields[1] + "/cmdline")
	if err != nil {
		return ErrConflict
	}
	if !exactDaemonConfigArgument(strings.Split(strings.TrimRight(string(args), "\x00"), "\x00"), file) {
		return ErrConflict
	}
	fd, err := unix.Open(file, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return ErrConflict
	}
	f := os.NewFile(uintptr(fd), file)
	defer f.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != 0 || before.Mode&0022 != 0 || before.Nlink != 1 || before.Size > 131072 {
		return ErrConflict
	}
	var real, boot unix.Timespec
	if unix.ClockGettime(unix.CLOCK_REALTIME, &real) != nil || unix.ClockGettime(unix.CLOCK_BOOTTIME, &boot) != nil {
		return ErrConflict
	}
	// Linux amd64 /proc reports USER_HZ=100. Quantization is conservative: a
	// config written in the same tick as startup is rejected, never guessed old.
	started := real.Nano() - boot.Nano() + int64(ticks)*10_000_000
	if before.Mtim.Nano() > started || before.Ctim.Nano() > started {
		return ErrConflict
	}
	raw, err := io.ReadAll(io.LimitReader(f, 131073))
	if err != nil || len(raw) > 131072 {
		return ErrConflict
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != expected || !matchingKataStartupConfig(raw, selector, shim, config) {
		return ErrConflict
	}
	if unix.Fstat(fd, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return ErrConflict
	}
	observed, err := peerIdentity(ctx, e.socket)
	if err != nil || observed != peer {
		return e.lost()
	}
	return nil
}
