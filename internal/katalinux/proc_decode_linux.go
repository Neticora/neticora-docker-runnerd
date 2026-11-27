//go:build linux

package katalinux

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

type procDecodeKey struct{}
type procFileIdentity struct{ Device, Inode uint64 }
type procMount struct {
	Device      uint64
	Root, Point string
}

// Memoize PURE decoding by exact freshly-read bytes, never by PID/TID/ns inode
// or by a prior absence result. Every examination still opens/reads each task's
// current maps/mountinfo and stats all FD/mountpoint/cwd/root references. The
// cache is bounded and discarded at the end of one cleanup request.
type procDecoder struct {
	mu             sync.Mutex
	mounts         map[string][]procMount
	maps           map[string]map[procFileIdentity]struct{}
	bytes, entries int
	scratch        sync.Pool
}

type procReadBuffer struct{ data []byte }

// Reuse storage, never its old contents: each open starts at offset zero and
// resets length to zero. The bytes are borrowed only until decoding completes.
func readProcCurrent(ctx context.Context, path string, limit int) ([]byte, func(), error) {
	d, _ := ctx.Value(procDecodeKey{}).(*procDecoder)
	var b *procReadBuffer
	if d != nil {
		if v := d.scratch.Get(); v != nil {
			b = v.(*procReadBuffer)
		}
	}
	if b == nil {
		b = &procReadBuffer{data: make([]byte, 0, 32<<10)}
	}
	b.data = b.data[:0]
	release := func() {
		if d != nil && cap(b.data) <= 1<<20 {
			b.data = b.data[:0]
			d.scratch.Put(b)
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, release, err
	}
	defer f.Close()
	empty := 0
	for {
		if err = ctx.Err(); err != nil {
			return nil, release, err
		}
		if len(b.data) == cap(b.data) {
			size := max(4096, 2*cap(b.data))
			if limit > 0 {
				size = min(size, limit+1)
			}
			next := make([]byte, len(b.data), size)
			copy(next, b.data)
			b.data = next
		}
		n, e := f.Read(b.data[len(b.data):cap(b.data)])
		b.data = b.data[:len(b.data)+n]
		if limit > 0 && len(b.data) > limit {
			return b.data, release, nil
		}
		if errors.Is(e, io.EOF) {
			return b.data, release, nil
		}
		if e != nil {
			return nil, release, e
		}
		if n == 0 {
			empty++
			if empty >= 100 {
				return nil, release, io.ErrNoProgress
			}
		} else {
			empty = 0
		}
	}
}

const procDecodeBudget = 16 << 20

func (d *procDecoder) reserve(size int) bool {
	if d.entries >= 128 || size > procDecodeBudget-d.bytes {
		return false
	}
	d.entries++
	d.bytes += size
	return true
}

func decodedMounts(ctx context.Context, raw []byte) ([]procMount, error) {
	d, _ := ctx.Value(procDecodeKey{}).(*procDecoder)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if d != nil {
		d.mu.Lock()
		found, ok := d.mounts[string(raw)]
		d.mu.Unlock()
		if ok {
			sandboxCount(ctx, "mountDecodeHit")
			return found, nil
		}
	}
	sandboxCount(ctx, "mountDecode")
	text := string(raw)
	var mounts []procMount
	for line := range strings.SplitSeq(strings.TrimSpace(text), "\n") {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var fields [6]string
		if procPrefixFields(line, fields[:]) < len(fields) {
			return nil, ErrQualification
		}
		device, err := sandboxMountDevice(fields[2])
		if err != nil {
			return nil, err
		}
		root, point := decodeSandboxMountPath(fields[3]), decodeSandboxMountPath(fields[4])
		if !filepath.IsAbs(point) || strings.Contains(point, "..") {
			return nil, ErrQualification
		}
		mounts = append(mounts, procMount{device, root, point})
	}
	if d != nil {
		d.mu.Lock()
		// Include retained raw bytes, decoded strings and conservative slice cost.
		size := len(text) + len(mounts)*96
		for _, m := range mounts {
			size += len(m.Root) + len(m.Point)
		}
		if d.reserve(size) {
			if d.mounts == nil {
				d.mounts = map[string][]procMount{}
			}
			d.mounts[text] = mounts
		}
		d.mu.Unlock()
	}
	return mounts, nil
}

func decodedMaps(ctx context.Context, raw []byte) (map[procFileIdentity]struct{}, error) {
	d, _ := ctx.Value(procDecodeKey{}).(*procDecoder)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if d != nil {
		d.mu.Lock()
		found, ok := d.maps[string(raw)]
		d.mu.Unlock()
		if ok {
			sandboxCount(ctx, "mapsDecodeHit")
			return found, nil
		}
	}
	sandboxCount(ctx, "mapsDecode")
	text := string(raw)
	refs := map[procFileIdentity]struct{}{}
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var fields [5]string
		if procPrefixFields(scanner.Text(), fields[:]) < len(fields) {
			return nil, ErrQualification
		}
		inode, err := strconv.ParseUint(fields[4], 10, 64)
		if err != nil {
			return nil, ErrQualification
		}
		majorText, minorText, ok := strings.Cut(fields[3], ":")
		if !ok {
			return nil, ErrQualification
		}
		major, e1 := strconv.ParseUint(majorText, 16, 32)
		minor, e2 := strconv.ParseUint(minorText, 16, 32)
		if e1 != nil || e2 != nil {
			return nil, ErrQualification
		}
		if inode != 0 {
			refs[procFileIdentity{unix.Mkdev(uint32(major), uint32(minor)), inode}] = struct{}{}
		}
	}
	if scanner.Err() != nil {
		return nil, ErrQualification
	}
	if d != nil {
		d.mu.Lock()
		if d.reserve(len(text) + len(refs)*96) {
			if d.maps == nil {
				d.maps = map[string]map[procFileIdentity]struct{}{}
			}
			d.maps[text] = refs
		}
		d.mu.Unlock()
	}
	return refs, nil
}

// A large maps file falls back to the existing streaming checker, not a new
// acceptance limit. Loop-device checks retain fresh map_files stat observations.
func noDecodedMapUsers(ctx context.Context, task string, r BlockRecord) error {
	sandboxCount(ctx, "mapsRead")
	raw, release, err := readProcCurrent(ctx, filepath.Join(task, "maps"), 1<<20)
	defer release()
	if errors.Is(err, os.ErrNotExist) {
		if _, e := os.Stat(task); errors.Is(e, os.ErrNotExist) {
			return nil
		}
	}
	if err != nil {
		return ErrQualification
	}
	if len(raw) > 1<<20 {
		return noMappedBlockUsersStream(ctx, task, r)
	}
	refs, err := decodedMaps(ctx, raw)
	if err != nil {
		return err
	}
	if _, held := refs[procFileIdentity{r.FileDevice, r.FileInode}]; held && r.FileInode != 0 {
		return sandboxReferenceHeld()
	}
	return ctx.Err()
}
