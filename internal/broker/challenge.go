package broker

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"time"
)

const challengeVersion = "runnerd-broker-challenge-v1"
const commitVersion = "runnerd-broker-commit-v1"
const commitDomain = "neticora-runnerd-broker-commit-v1\n"

type Challenge struct {
	Version   string                `json:"version"`
	Request   ExecutionGrantRequest `json:"request"`
	ExpiresAt string                `json:"expiresAt"`
	State     string                `json:"state"`
	GrantHash string                `json:"grantHash,omitempty"`
	Binding   *Binding              `json:"binding,omitempty"`
}

type Commit struct {
	Version     string  `json:"version"`
	Audience    string  `json:"audience"`
	OperationID string  `json:"operationId"`
	GrantHash   string  `json:"grantHash"`
	Challenge   string  `json:"challenge"`
	Binding     Binding `json:"binding"`
	State       string  `json:"state"`
	NotBefore   string  `json:"notBefore"`
	ExpiresAt   string  `json:"expiresAt"`
}

type SignedCommit struct {
	Commit    Commit `json:"commit"`
	Signature string `json:"signature"`
}

type CommitRequest struct {
	Request ExecutionGrantRequest `json:"request"`
	Grant   SignedExecutionGrant  `json:"grant"`
}

func DecodeCommit(raw []byte) (SignedCommit, error) {
	var c SignedCommit
	err := decode(raw, &c)
	return c, err
}

func signedGrantHash(s SignedExecutionGrant) string {
	raw, err := canonical(s)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

// IssueChallenge ignores no caller entropy: a non-empty supplied challenge is
// rejected. Repeated issuance returns the same live outstanding challenge.
func (l *Ledger) IssueChallenge(r ExecutionGrantRequest, now time.Time) (Challenge, error) {
	if r.Challenge != "" {
		return Challenge{}, ErrRejected
	}
	r.Challenge = hex.EncodeToString(make([]byte, 32))
	if r.Validate() != nil {
		return Challenge{}, ErrRejected
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	root, err := l.records("challenges")
	if err != nil {
		return Challenge{}, err
	}
	defer root.Close()
	var old Challenge
	err = readRecord(root, r.OperationID, &old)
	if err == nil {
		expires, e := time.Parse(time.RFC3339Nano, old.ExpiresAt)
		if e != nil || old.Version != challengeVersion || old.Request.Validate() != nil || old.Request.OperationID != r.OperationID || (old.State != "ISSUED" && old.State != "CONSUMED") {
			return Challenge{}, ErrRejected
		}
		if old.State == "CONSUMED" {
			return Challenge{}, ErrConflict
		}
		if now.Before(expires) {
			return old, nil
		}
	} else if !os.IsNotExist(err) {
		return Challenge{}, err
	}
	if os.IsNotExist(err) {
		dir, e := root.Open(".")
		if e != nil {
			return Challenge{}, e
		}
		names, e := dir.Readdirnames(10001)
		_ = dir.Close()
		if (e != nil && e != io.EOF) || len(names) >= 10000 {
			return Challenge{}, ErrRejected
		}
	}
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return Challenge{}, err
	}
	r.Challenge = hex.EncodeToString(nonce[:])
	c := Challenge{Version: challengeVersion, Request: r, ExpiresAt: now.Add(15 * time.Second).UTC().Format(time.RFC3339Nano), State: "ISSUED"}
	if err = l.writeRecord(root, r.OperationID, c); err != nil {
		return Challenge{}, err
	}
	return c, nil
}

func verifyCommit(c SignedCommit, s SignedExecutionGrant, key ed25519.PublicKey, now time.Time) error {
	v := c.Commit
	if len(key) != ed25519.PublicKeySize || v.Version != commitVersion || v.State != "COMMITTED" || v.Audience != s.Grant.Audience || v.OperationID != s.Grant.OperationID || v.Challenge != s.Grant.Challenge || v.Binding != s.Grant.Binding || v.GrantHash != signedGrantHash(s) {
		return ErrRejected
	}
	start, e1 := time.Parse(time.RFC3339Nano, v.NotBefore)
	end, e2 := time.Parse(time.RFC3339Nano, v.ExpiresAt)
	grantEnd, e3 := time.Parse(time.RFC3339Nano, s.Grant.ExpiresAt)
	if e1 != nil || e2 != nil || e3 != nil || !end.After(start) || end.After(grantEnd) || now.Before(start) || !now.Before(end) || end.Sub(start) > 15*time.Second {
		return ErrRejected
	}
	raw, err := canonical(v)
	if err != nil {
		return ErrRejected
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(c.Signature)
	if err != nil || !ed25519.Verify(key, append([]byte(commitDomain), raw...), signature) {
		return ErrRejected
	}
	return nil
}

// consumeChallenge is called under the ledger lock, before any physical effect.
// A duplicate can reconcile the original intent, never receive fresh authority.
func (l *Ledger) consumeChallenge(s SignedExecutionGrant, r ExecutionGrantRequest, c SignedCommit, key ed25519.PublicKey, now time.Time) (bool, error) {
	if verifyCommit(c, s, key, now) != nil {
		return false, ErrRejected
	}
	root, err := l.records("challenges")
	if err != nil {
		return false, err
	}
	defer root.Close()
	var challenge Challenge
	if err = readRecord(root, r.OperationID, &challenge); err != nil {
		return false, err
	}
	expires, err := time.Parse(time.RFC3339Nano, challenge.ExpiresAt)
	if err != nil || challenge.Version != challengeVersion || challenge.Request != r || !now.Before(expires) {
		return false, ErrRejected
	}
	if challenge.State == "CONSUMED" {
		if challenge.GrantHash != signedGrantHash(s) || challenge.Binding == nil || *challenge.Binding != s.Grant.Binding {
			return false, ErrConflict
		}
		return true, nil
	}
	if challenge.State != "ISSUED" || challenge.GrantHash != "" || challenge.Binding != nil {
		return false, ErrRejected
	}
	challenge.State = "CONSUMED"
	challenge.GrantHash = signedGrantHash(s)
	bound := s.Grant.Binding
	challenge.Binding = &bound
	if err = l.writeRecord(root, r.OperationID, challenge); err != nil {
		return false, err
	}
	return false, nil
}
