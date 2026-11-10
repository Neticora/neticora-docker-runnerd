//go:build linux && runnerd_qualification

package journal

import (
	"errors"
	"os"
)

// SetQualificationFaultBeforeRun exposes the existing transaction barriers only
// in explicitly tagged lab builds. Call before starting any concurrent operation.
// Normal daemon/release builds have neither this API nor an environment hook.
func (s *SQLiteStore) SetQualificationFaultBeforeRun(fault func(string) error) error {
	if os.Getenv("RUNNERD08_LIVE_QUALIFICATION") != "1" && os.Getenv("RUNNERD09_LIVE_QUALIFICATION") != "1" {
		return errors.New("explicit live qualification opt-in required")
	}
	if _, err := os.Stat("/etc/neticora-runnerd-lab"); err != nil {
		return errors.New("disposable lab required")
	}
	s.fault = fault
	return nil
}
