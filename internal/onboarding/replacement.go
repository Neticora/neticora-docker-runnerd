package onboarding

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/identity"
)

const maxTokenReplacements = 16

type tokenReplacement struct {
	RequestID         string `json:"requestId"`
	Fingerprint       string `json:"fingerprint"`
	PreviousTokenHash string `json:"previousTokenHash"`
	TokenHash         string `json:"tokenHash"`
}

// Append-only replacement records are synced before network effects. The
// original attempt/key remain immutable. All previous hashes travel in the
// signed request, so an unknown earlier outcome cannot authorize another host.
func enrollmentMessage(o Options, key ed25519.PrivateKey, a attempt, token []byte) (protocol.Outbound, error) {
	var zero protocol.Outbound
	hashes := []string{a.TokenHash}
	gap := false
	for i := 1; i <= maxTokenReplacements; i++ {
		path := replacementPath(o, i)
		present, err := exists(path)
		if err != nil {
			return zero, ErrState
		}
		if !present {
			gap = true
			continue
		}
		var r tokenReplacement
		if gap || readJSON(path, &r) != nil || r.RequestID != a.RequestID || r.Fingerprint != a.Fingerprint || r.PreviousTokenHash != hashes[len(hashes)-1] {
			return zero, ErrState
		}
		decoded, err := hex.DecodeString(r.TokenHash)
		if err != nil || len(decoded) != 32 {
			return zero, ErrState
		}
		for _, old := range hashes {
			if old == r.TokenHash {
				return zero, ErrState
			}
		}
		hashes = append(hashes, r.TokenHash)
	}
	current := digest(token)
	selected := -1
	for i, old := range hashes {
		if old == current {
			selected = i
			break
		}
	}
	appendRecord := selected < 0
	if appendRecord {
		if !o.ReplaceToken {
			return zero, errors.New("retry requires a saved enrollment token; use setup --replace-token for an unused original attempt")
		}
		if len(hashes) > maxTokenReplacements {
			return zero, errors.New("enrollment token replacement limit reached; preserve state for operator recovery")
		}
		selected = len(hashes)
	}
	var replacement *protocol.EnrollmentTokenReplacement
	if selected > 0 {
		if err := unfinishedReplacement(o); err != nil {
			return zero, err
		}
		replacement = &protocol.EnrollmentTokenReplacement{TenantId: a.TenantID, RunnerDeploymentId: a.PoolID, PriorTokenHashes: hashes[:selected]}
	}
	message, err := identity.EnrollmentReplacing(key, a.RequestID, string(token), replacement)
	if err != nil {
		return zero, err
	}
	if appendRecord {
		if err = checkpoint(o, "before-token-replacement"); err != nil {
			return zero, err
		}
		r := tokenReplacement{RequestID: a.RequestID, Fingerprint: a.Fingerprint, PreviousTokenHash: hashes[len(hashes)-1], TokenHash: current}
		if err = saveJSON(replacementPath(o, selected), r); err != nil {
			return zero, err
		}
		if err = checkpoint(o, "after-token-replacement"); err != nil {
			return zero, err
		}
	}
	return message, nil
}

func replacementPath(o Options, index int) string {
	return filepath.Join(o.SetupDir, fmt.Sprintf("token-replacement-%02d.json", index))
}

func unfinishedReplacement(o Options) error {
	for _, path := range []string{o.ConfigPath, o.CredentialPath, filepath.Join(o.SetupDir, "enrollment.json")} {
		if yes, err := exists(path); err != nil || yes {
			return errors.New("enrollment already has installation state; token replacement is disabled")
		}
	}
	entries, err := os.ReadDir(o.StateDir)
	if err != nil {
		return ErrState
	}
	for _, entry := range entries {
		if entry.Name() != "instance.lock" {
			return errors.New("existing runtime state prevents enrollment token replacement")
		}
	}
	return nil
}
