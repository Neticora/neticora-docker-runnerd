//go:build linux

package updatetrust

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/testing/data"
)

func TestOfflineRealSigstoreCertificateAndTransparencyProof(t *testing.T) {
	// Immutable upstream fixture is a real public-good GitHub attestation, not a
	// locally fabricated GitHub certificate or a stub verifier. This qualifies
	// crypto/identity enforcement, not issuance of a Neticora candidate.
	b := data.Bundle(t, "sigstore.js@2.0.0-provenance.sigstore.json")
	material := data.TrustedRoot(t, "public-good.json")
	bundleJSON, err := b.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	rootJSON, err := material.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	content, err := b.VerificationContent()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := certificate.SummarizeCertificate(content.Certificate())
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := Bootstrap{Repository: cert.SourceRepositoryURI, SourceRef: cert.SourceRepositoryRef, RepositoryID: cert.SourceRepositoryIdentifier, OwnerID: cert.SourceRepositoryOwnerIdentifier, Issuer: cert.Issuer, Subject: cert.SubjectAlternativeName}
	bootstrap.SigstoreRootSHA256 = sha(rootJSON)
	// The digest is pinned by the independently versioned upstream vector.
	var envelope struct {
		DSSE struct {
			Payload []byte `json:"payload"`
		} `json:"dsseEnvelope"`
	}
	if err = json.Unmarshal(bundleJSON, &envelope); err != nil {
		t.Fatal(err)
	}
	var statement struct {
		Subject []struct {
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	if err = json.Unmarshal(envelope.DSSE.Payload, &statement); err != nil || len(statement.Subject) != 1 {
		t.Fatal("upstream subject missing")
	}
	digest, err := hex.DecodeString(statement.Subject[0].Digest["sha512"])
	if err != nil {
		t.Fatal(err)
	}
	if _, err = githubStatement(bootstrap, rootJSON, bundleJSON, "sha512", digest, cert.SourceRepositoryDigest, nil); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"issuer", "subject", "source", "owner", "digest", "root"} {
		t.Run(kind, func(t *testing.T) {
			expected := bootstrap
			source := cert.SourceRepositoryDigest
			hash := append([]byte{}, digest...)
			roots := rootJSON
			switch kind {
			case "issuer":
				expected.Issuer = "https://invalid.example"
			case "subject":
				expected.Subject += "-wrong"
			case "source":
				source = "wrong"
			case "owner":
				expected.OwnerID = "wrong"
			case "digest":
				hash[0] ^= 1
			case "root":
				roots = []byte(`{}`)
			}
			if _, err := githubStatement(expected, roots, bundleJSON, "sha512", hash, source, nil); err == nil {
				t.Fatal("invalid signature policy accepted")
			}
		})
	}
	key, err := x509.MarshalPKIXPublicKey(content.Certificate().PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = githubStatement(bootstrap, rootJSON, bundleJSON, "sha512", digest, cert.SourceRepositoryDigest, map[string]bool{sha(key): true}); err == nil {
		t.Fatal("revoked Sigstore signing key accepted")
	}
}
