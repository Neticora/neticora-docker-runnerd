//go:build linux

package execution

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/agent"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
	"github.com/Neticora/neticora-docker-runnerd/internal/peerrecovery"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
	"github.com/Neticora/neticora-docker-runnerd/journal"
	"github.com/Neticora/neticora-docker-runnerd/transport"
)

func actualBootID() (string, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", agent.ErrRecoveryRequired
	}
	value := strings.TrimSpace(string(raw))
	if len(value) < 16 || len(value) > 128 {
		return "", agent.ErrRecoveryRequired
	}
	return value, nil
}

// AdministrativePeerRecovery runs under the journal's exclusive installation
// owner with the normal daemon stopped. Inspection opens Docker read-only;
// apply accepts only committed independent approval. No signer key is loaded.
func AdministrativePeerRecovery(ctx context.Context, c config.Config, operation, inputPath, publicKeyPath string) ([]byte, error) {
	if operation == "diagnose" {
		return diagnosePeerRecovery(ctx, c)
	}
	x := c.Execution
	if x == nil || !x.Enabled || os.Geteuid() == 0 || (operation != "inspect" && operation != "apply") {
		return nil, ErrReconcile
	}
	credentials, key, err := ReadCredentials(c.CredentialFile)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	actualBoot, err := actualBootID()
	if err != nil {
		return nil, err
	}
	input, err := hostfs.ReadPrivate(inputPath, 4<<20)
	if err != nil {
		return nil, err
	}
	var challenge protocol.PeerRecoveryChallenge
	var approved protocol.SignedPeerRecoveryApproval
	if operation == "inspect" {
		challenge, err = protocol.DecodePeerRecoveryChallenge(input)
	} else {
		approved, err = protocol.DecodeSignedPeerRecoveryApproval(input)
		challenge = approved.Manifest.Plan.Challenge
	}
	if err != nil || challenge.TenantId != credentials.TenantID || challenge.Identity.HostId != credentials.Identity.HostId || challenge.Identity.KeyId != credentials.Identity.KeyId || challenge.Identity.KeyVersion != credentials.Identity.KeyVersion {
		return nil, ErrReconcile
	}
	oldEpoch, e1 := strconv.ParseUint(credentials.Identity.SessionEpoch, 10, 64)
	newEpoch, e2 := strconv.ParseUint(challenge.Identity.SessionEpoch, 10, 64)
	if e1 != nil || e2 != nil || newEpoch < oldEpoch {
		return nil, ErrReconcile
	}
	// The supplied epoch is never written here or authenticated implicitly. The
	// platform must already have accepted administrator resynchronization; its
	// normal assertion verifier decides whether these current credentials work.
	credentials.Identity = challenge.Identity
	credentials.BootID = actualBoot
	if err = persistRecoveryDrain(c.StateDir); err != nil {
		return nil, err
	}
	store, err := journal.OpenRecovery(ctx, c.StateDir, journal.Options{})
	if err != nil {
		return nil, err
	}
	defer store.Close()
	runtime, err := dockerengine.OpenReadOnly(c.RuntimeEndpoint, credentials.InstallationID, nil)
	if err != nil {
		return nil, err
	}
	defer runtime.Close()
	var ca []byte
	if x.CustomCAFile != "" {
		ca, err = hostfs.ReadPrivate(x.CustomCAFile, 1<<20)
		if err != nil {
			return nil, err
		}
	}
	client, err := transport.NewWithRoots(c.ControlPlaneURL, c.Timeout(), ca)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	remote := &HostRemote{Client: client, Credentials: credentials, Key: key, Version: Version()}
	coordinator := &PeerRecoveryCoordinator{Store: store, Runtime: runtime, Remote: remote, Profile: standardlinux.Settings{ImageRepository: x.ImageRepository, NetworkID: x.NetworkID, BootstrapRoot: x.BootstrapRoot, RunnerUID: os.Geteuid(), PidsLimit: x.PidsLimit}, Identity: credentials.Identity, TenantID: credentials.TenantID, InstallationID: credentials.InstallationID, BootID: actualBoot, AgentVersion: Version()}
	if x.Kata != nil {
		coordinator.Kata, err = katalinux.Load(x.Kata.ProfileFile, x.Kata.PublicKeyFile, x.Kata.EvidenceDirectory, c.StateDir, coordinator.Profile)
		if err != nil {
			return nil, err
		}
		coordinator.Kata.ObserverSocket = x.Kata.ObserverSocket
		if err = coordinator.Kata.ProtectPaths(c.CredentialFile, x.KeysDirectory, x.PolicyFile, x.CapabilitiesFile, x.TrustRoots, x.ImageBundles, x.CustomCAFile, x.Kata.ObserverSocket); err != nil {
			return nil, err
		}
	}
	if operation == "inspect" {
		plan, err := coordinator.Propose(ctx, challenge, key)
		if err != nil {
			return nil, err
		}
		return peerrecovery.Canonical(plan)
	}
	coordinator.PublicKey, err = hostfs.ReadPrivate(publicKeyPath, 16384)
	if err != nil {
		return nil, err
	}
	if err = coordinator.Apply(ctx, approved); err != nil {
		return nil, err
	}
	// Only after verified cleanup, final native ACKs and platform completion may
	// credentials follow the approved peer. The local drain remains in force;
	// new qualification and an explicit resume remain separate operator steps.
	if err = commitRecoveredCredentials(c.CredentialFile, credentials, approved.Manifest.Plan.TargetEndpointIdentity); err != nil {
		return nil, err
	}
	return peerrecovery.Canonical(map[string]string{"approvalId": approved.Manifest.ApprovalId, "state": "completed-drained"})
}

func persistRecoveryDrain(dir string) error {
	if err := hostfs.CheckAncestors(dir); err != nil {
		return err
	}
	path := filepath.Join(dir, "admission.drained")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		_, err = hostfs.ReadPrivate(path, 0)
		return err
	}
	if err != nil {
		return err
	}
	err = f.Sync()
	closed := f.Close()
	if err != nil {
		return err
	}
	if closed != nil {
		return closed
	}
	return syncRecoveryDirectory(dir)
}
func syncRecoveryDirectory(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func commitRecoveredCredentials(path string, current Credentials, endpoint string) error {
	raw, err := hostfs.ReadPrivate(path, 65536)
	if err != nil {
		return err
	}
	defer clear(raw)
	var document map[string]json.RawMessage
	if json.Unmarshal(raw, &document) != nil {
		return ErrReconcile
	}
	stored, private, err := ReadCredentials(path)
	if err != nil {
		return err
	}
	defer clear(private)
	if stored.InstallationID != current.InstallationID || stored.TenantID != current.TenantID || stored.Identity.HostId != current.Identity.HostId || stored.Identity.KeyId != current.Identity.KeyId || stored.Identity.KeyVersion != current.Identity.KeyVersion {
		return ErrReconcile
	}
	document["identity"], _ = json.Marshal(current.Identity)
	document["bootId"], _ = json.Marshal(current.BootID)
	document["endpointIdentity"], _ = json.Marshal(endpoint)
	encoded, err := json.Marshal(document)
	if err != nil {
		return err
	}
	defer clear(encoded)
	nonce := make([]byte, 12)
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	temporary := filepath.Join(filepath.Dir(path), ".recovery-identity-"+hex.EncodeToString(nonce))
	f, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(temporary)
	_, err = f.Write(encoded)
	if err == nil {
		err = f.Sync()
	}
	closed := f.Close()
	if err != nil {
		return err
	}
	if closed != nil {
		return closed
	}
	if err = os.Rename(temporary, path); err != nil {
		return err
	}
	return syncRecoveryDirectory(filepath.Dir(path))
}

// diagnosePeerRecovery intentionally requires neither host credentials nor a
// live platform. Its unsigned, distinct-purpose report cannot become approval.
func diagnosePeerRecovery(ctx context.Context, c config.Config) ([]byte, error) {
	if os.Geteuid() == 0 {
		return nil, ErrReconcile
	}
	if err := persistRecoveryDrain(c.StateDir); err != nil {
		return nil, err
	}
	store, err := journal.OpenRecovery(ctx, c.StateDir, journal.Options{})
	if err != nil {
		return nil, err
	}
	defer store.Close()
	scope, err := store.PeerRecoveryScope(ctx)
	if err != nil {
		return nil, err
	}
	runtime, err := dockerengine.OpenReadOnly(c.RuntimeEndpoint, scope.InstallationID, nil)
	if err != nil {
		return nil, err
	}
	defer runtime.Close()
	report := map[string]any{"domain": "neticora-runnerd-peer-recovery-diagnostic-v1", "admissionEnabled": false, "mutationsEnabled": false, "sourceEndpointIdentity": scope.EndpointIdentity, "journal": store.Health(ctx), "observedAt": time.Now().UTC().Format(wireTime)}
	rows := []any{}
	cursor := agent.ExecutionCursor{}
	for {
		page, err := store.Incomplete(ctx, cursor, 100)
		if err != nil {
			return nil, err
		}
		if len(rows)+len(page) > 1000 {
			return nil, ErrReconcile
		}
		for _, e := range page {
			rows = append(rows, map[string]any{"executionId": e.Identity.ExecutionID, "generation": e.Identity.Generation, "specHash": e.Identity.SpecHash, "state": e.State, "cleanupPending": e.CleanupPending, "lastSequence": e.LastSequence, "ackSequence": e.AckSequence})
		}
		if len(page) < 100 {
			break
		}
		last := page[len(page)-1]
		cursor = agent.ExecutionCursor{ExecutionID: last.Identity.ExecutionID, Generation: last.Identity.Generation}
	}
	report["executions"] = rows
	peer, err := runtime.Probe(ctx)
	if err != nil {
		report["inventoryComplete"] = false
		report["runtimeStatus"] = "unavailable-or-fenced"
		return peerrecovery.Canonical(report)
	}
	ids, err := runtime.Inventory(ctx)
	if err != nil {
		report["inventoryComplete"] = false
		report["runtimeStatus"] = "unavailable-or-fenced"
		return peerrecovery.Canonical(report)
	}
	after, err := runtime.Probe(ctx)
	if err != nil || after != peer {
		report["inventoryComplete"] = false
		report["runtimeStatus"] = "continuity-lost"
		return peerrecovery.Canonical(report)
	}
	report["observedEndpointIdentity"] = peer
	report["ownedResourceIds"] = ids
	report["inventoryComplete"] = true
	report["runtimeStatus"] = "read-only-inspection"
	return peerrecovery.Canonical(report)
}
