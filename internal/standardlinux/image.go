package standardlinux

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"path/filepath"
	"regexp"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"

	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// ImageVerifier verifies provisioned offline Sigstore image attestations. Roots
// and freshness originate from protected local configuration, never the image or
// an incoming command. Revocation is provisioned by withdrawing the digest or
// root in a newer local policy; no indefinitely valid verification cache exists.
type ImageVerifier struct {
	RootDirectory   string
	BundleDirectory string
	ProvisionedAt   time.Time
}

func (v ImageVerifier) Verify(ctx context.Context, p *Policy, repository, digest string, now time.Time) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if p == nil {
		return ErrAdmission
	}
	i := p.value.Images
	expires, err := time.Parse(time.RFC3339Nano, i.TrustExpiresAt)
	if err != nil || !expires.After(now) || v.ProvisionedAt.IsZero() || v.ProvisionedAt.After(now) || now.Sub(v.ProvisionedAt) > time.Duration(i.MaxOfflineAgeSeconds)*time.Second || !regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`).MatchString(i.TrustRootId) || !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(digest) {
		return ErrAdmission
	}
	raw, err := hostfs.ReadPrivate(filepath.Join(v.RootDirectory, i.TrustRootId+"-"+i.TrustRootVersion+".json"), 4<<20)
	if err != nil {
		return ErrAdmission
	}
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != i.TrustRootSha256 {
		return ErrAdmission
	}
	var pinned struct {
		Version string `json:"version"`
	}
	_ = json.Unmarshal(raw, &pinned)
	if pinned.Version == "neticora-image-key-v1" {
		signatures, e := hostfs.ReadPrivate(filepath.Join(v.BundleDirectory, digest[7:]+".sigstore.json"), 4<<20)
		if e != nil {
			return ErrAdmission
		}
		return verifyPinnedKey(raw, signatures, p, repository, digest, now)
	}
	material, err := root.NewTrustedRootFromJSON(raw)
	if err != nil {
		return ErrAdmission
	}
	checker, err := verify.NewVerifier(material, verify.WithSignedCertificateTimestamps(1), verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	if err != nil {
		return ErrAdmission
	}
	raw, err = hostfs.ReadPrivate(filepath.Join(v.BundleDirectory, digest[7:]+".sigstore.json"), 4<<20)
	if err != nil {
		return ErrAdmission
	}
	var signed bundle.Bundle
	if signed.UnmarshalJSON(raw) != nil {
		return ErrAdmission
	}
	identity, err := verify.NewShortCertificateIdentity(i.TrustedIssuer, "", i.TrustedSubject, "")
	if err != nil {
		return ErrAdmission
	}
	bytes, err := hex.DecodeString(digest[7:])
	if err != nil {
		return ErrAdmission
	}
	result, err := checker.Verify(&signed, verify.NewPolicy(verify.WithArtifactDigest("sha256", bytes), verify.WithCertificateIdentity(identity)))
	if err != nil || result.Statement == nil || len(result.Statement.Subject) != 1 || result.Statement.Subject[0].Name != repository || result.Statement.Subject[0].Digest["sha256"] != digest[7:] {
		return ErrAdmission
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

// Pinned-key mode consumes cosign download signature output, matching the
// existing image publisher. Root metadata is independently provisioned and
// hash-pinned by policy; an artifact cannot select or supply its own authority.
func verifyPinnedKey(raw, signatures []byte, p *Policy, repository, digest string, now time.Time) error {
	var authority struct {
		Version      string `json:"version"`
		RootID       string `json:"rootId"`
		RootVersion  string `json:"rootVersion"`
		Issuer       string `json:"issuer"`
		Subject      string `json:"subject"`
		ValidUntil   string `json:"validUntil"`
		PublicKeyPEM string `json:"publicKeyPem"`
	}
	if _, err := protocol.CanonicalizeJSON(raw); err != nil {
		return ErrAdmission
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 7 || json.Unmarshal(raw, &authority) != nil {
		return ErrAdmission
	}
	for _, name := range []string{"version", "rootId", "rootVersion", "issuer", "subject", "validUntil", "publicKeyPem"} {
		if fields[name] == nil {
			return ErrAdmission
		}
	}
	expires, err := time.Parse(time.RFC3339Nano, authority.ValidUntil)
	i := p.value.Images
	if err != nil || !expires.After(now) || authority.RootID != i.TrustRootId || authority.RootVersion != i.TrustRootVersion || authority.Issuer != i.TrustedIssuer || authority.Subject != i.TrustedSubject {
		return ErrAdmission
	}
	block, rest := pem.Decode([]byte(authority.PublicKeyPEM))
	if block == nil || len(rest) != 0 || block.Type != "PUBLIC KEY" {
		return ErrAdmission
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return ErrAdmission
	}
	public, ok := key.(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P256() {
		return ErrAdmission
	}
	if _, err = protocol.CanonicalizeJSON(signatures); err != nil {
		return ErrAdmission
	}
	var rows []struct {
		Payload   string `json:"payload"`
		Signature string `json:"base64Signature"`
	}
	if json.Unmarshal(signatures, &rows) != nil || len(rows) == 0 || len(rows) > 16 {
		return ErrAdmission
	}
	for _, row := range rows {
		payload, e := base64.StdEncoding.DecodeString(row.Payload)
		if e != nil || len(payload) > 65536 {
			continue
		}
		sig, e := base64.StdEncoding.DecodeString(row.Signature)
		if e != nil {
			continue
		}
		hash := sha256.Sum256(payload)
		if !ecdsa.VerifyASN1(public, hash[:], sig) {
			continue
		}
		if _, e = protocol.CanonicalizeJSON(payload); e != nil {
			continue
		}
		var claim struct {
			Critical struct {
				Identity struct {
					Repository string `json:"docker-reference"`
				} `json:"identity"`
				Image struct {
					Digest string `json:"docker-manifest-digest"`
				} `json:"image"`
				Type string `json:"type"`
			} `json:"critical"`
		}
		if json.Unmarshal(payload, &claim) == nil && claim.Critical.Type == "cosign container image signature" && claim.Critical.Identity.Repository == repository && claim.Critical.Image.Digest == digest {
			return nil
		}
	}
	return ErrAdmission
}
