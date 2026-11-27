//go:build linux

package dockerengine

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func checkQuotaFilesystem(root string) error {
	var stat syscall.Statfs_t
	if syscall.Statfs(root, &stat) != nil || stat.Type != 0x58465342 {
		return ErrConflict
	}
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return ErrConflict
	}
	longest := ""
	qualified := false
	for _, line := range strings.Split(string(raw), "\n") {
		halves := strings.SplitN(line, " - ", 2)
		if len(halves) != 2 {
			continue
		}
		a, b := strings.Fields(halves[0]), strings.Fields(halves[1])
		if len(a) < 6 || len(b) < 3 {
			continue
		}
		point := a[4]
		rel, e := filepath.Rel(point, root)
		if e != nil || rel == ".." || strings.HasPrefix(rel, "../") || len(point) < len(longest) {
			continue
		}
		longest = point
		opts := "," + a[5] + "," + b[2] + ","
		qualified = b[0] == "xfs" && (strings.Contains(opts, ",pquota,") || strings.Contains(opts, ",prjquota,"))
	}
	if longest == "" || !qualified {
		return ErrConflict
	}
	return nil
}
