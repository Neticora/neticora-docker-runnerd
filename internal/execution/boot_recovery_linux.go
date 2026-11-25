//go:build linux

package execution

import (
	"context"
	"errors"
	"log"
	"os"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
)

// RecoverOnBoot consumes a committed, independently signed approval for this
// boot before the service opens the journal for normal execution. It leaves the
// old binding drained until an operator installs a new launch qualification.
func RecoverOnBoot(ctx context.Context, c config.Config, approvalPath, publicKeyPath string) error {
	if !c.StandaloneExecution() || approvalPath == "" || publicKeyPath == "" || c.Execution.Kata.QualificationBindingFile != "" || c.Execution.Kata.QualificationAuthorityPin != "" {
		return ErrKataOnly
	}
	credentials, key, err := ReadCredentials(c.CredentialFile)
	clear(key)
	if err != nil {
		return err
	}
	boot, err := actualBootID()
	if err != nil || credentials.BootID == boot {
		return err
	}
	log.Print("Waiting for an independently signed peer recovery approval for the current boot")
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		if _, err := os.Lstat(approvalPath); !errors.Is(err, os.ErrNotExist) {
			raw, err := hostfs.ReadPrivate(approvalPath, 4<<20)
			if err != nil {
				return err
			}
			approved, err := protocol.DecodeSignedPeerRecoveryApproval(raw)
			if err != nil {
				return err
			}
			if approved.Manifest.Plan.BootId == boot {
				if _, err = AdministrativePeerRecovery(ctx, c, "apply", approvalPath, publicKeyPath); err != nil {
					return err
				}
				log.Print("Signed peer recovery completed; workload admission stays drained")
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
