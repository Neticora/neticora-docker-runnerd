package broker

import (
	"crypto/ed25519"
	"io"
	"strings"
	"time"
)

// AcceptExecutionIntent records independently authorized pending work, not a
// runtime effect. Live grant consumption and resource-state verification must
// additionally precede any future mutation.
func (l *Ledger) AcceptExecutionIntent(s SignedExecutionGrant, r ExecutionGrantRequest, key ed25519.PublicKey, scope Binding, now time.Time, commits ...SignedCommit) (Receipt, bool, error) {
	if len(commits) != 1 || verifyCommit(commits[0], s, key, now) != nil {
		return Receipt{}, false, ErrRejected
	}
	if VerifyExecutionGrant(s, r, key, scope, now) != nil {
		return Receipt{}, false, ErrRejected
	}
	// Only initial intent revision exists; arbitrary revisions cannot mint state.
	if r.ExpectedRevision != "0" {
		return Receipt{}, false, ErrConflict
	}
	payload, err := s.Grant.IntentPayload()
	if err != nil {
		return Receipt{}, false, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failed {
		return Receipt{}, false, ErrRejected
	}
	if err := l.checkLaunchFence(r, s.Grant.Binding); err != nil {
		return Receipt{}, false, err
	}
	if _, err = l.consumeChallenge(s, r, commits[0], key, now); err != nil {
		return Receipt{}, false, err
	}
	return l.begin(r.OperationID, r.Operation, s.Grant.Binding, payload)
}

func (l *Ledger) checkLaunchFence(r ExecutionGrantRequest, binding Binding) error {
	if r.Operation == "CreateExecution" || r.Operation == "StartExecution" || r.Operation == "PrepareImage" {
		dir, err := l.root.Open(".")
		if err != nil {
			return err
		}
		defer dir.Close()
		count := 0
		for {
			names, err := dir.Readdirnames(64)
			if err != nil && err != io.EOF {
				return err
			}
			for _, name := range names {
				count++
				if count > 10000 {
					return ErrRejected
				}
				if name == "instance.lock" {
					continue
				}
				if name == "challenges" || name == "resources" || name == "handoffs" {
					info, e := l.root.Lstat(name)
					if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
						return ErrRejected
					}
					continue
				}
				if !strings.HasSuffix(name, ".json") {
					return ErrRejected
				}
				old, e := l.read(strings.TrimSuffix(name, ".json"))
				if e != nil {
					return e
				}
				b := old.Binding
				if b.InstallationID == binding.InstallationID && b.ExecutionID == r.ExecutionID {
					if b.Generation != r.Generation || b.SpecHash != binding.SpecHash || b.AttemptID != binding.AttemptID {
						return ErrConflict
					}
					if old.Operation == "StopExecution" || old.Operation == "RemoveExecution" || old.Operation == "DisposeUnstarted" || old.Operation == "CleanupExecutionResources" {
						return ErrConflict
					}
				}
			}
			if err == io.EOF {
				break
			}
		}
	}
	return nil
}
