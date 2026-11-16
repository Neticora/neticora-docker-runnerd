//go:build linux

package onboarding

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"github.com/Neticora/neticora-docker-runnerd/internal/connectionrecovery"
	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
	"github.com/Neticora/neticora-docker-runnerd/internal/execution"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/journal"
	"github.com/Neticora/neticora-docker-runnerd/transport"
	"golang.org/x/term"
	"path/filepath"
)

const configPath = "/etc/neticora-runnerd/config.json"

// Command handles only explicit installed-product commands. No token arguments
// or environment variables are accepted. Root initializes the service account's
// configured groups instead of inheriting any groups from the invoking caller.
func Command(args []string) (bool, error) {
	if len(args) == 0 || (args[0] != "setup" && args[0] != "status" && args[0] != "doctor" && args[0] != "prepare-execution" && args[0] != "enable-startup") {
		return false, nil
	}
	replaceToken := len(args) == 2 && args[0] == "setup" && args[1] == "--replace-token"
	prepare := len(args) == 2 && args[0] == "prepare-execution"
	if len(args) != 1 && !replaceToken && !prepare {
		return true, errors.New("usage: neticora-runnerd setup [--replace-token]|status|doctor|prepare-execution FILE")
	}
	identity, e := resolveServiceIdentity()
	if e != nil {
		return true, e
	}
	if os.Geteuid() == 0 {
		return true, commandAsService(args, identity)
	}
	if e = identity.verifyCurrent(); e != nil {
		return true, e
	}
	if args[0] == "prepare-execution" {
		if !prepare {
			return true, errors.New("usage: neticora-runnerd prepare-execution ABSOLUTE_CONFIG_FILE")
		}
		raw, err := hostfs.ReadPrivate(args[1], config.MaxConfigBytes)
		if err != nil {
			return true, errors.New("protected preparation configuration unavailable; installation unchanged")
		}
		defer clear(raw)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		report := execution.PrepareExecution(ctx, raw, time.Now())
		if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
			return true, err
		}
		if !report.ConfigurationValid {
			return true, errors.New("execution preparation blocked; no configuration, authority or recovery state changed")
		}
		return true, nil
	}
	if args[0] == "enable-startup" {
		raw, err := hostfs.ReadPrivate(configPath, config.MaxConfigBytes)
		if err != nil {
			return true, err
		}
		c, err := config.Parse(raw)
		if err != nil {
			return true, err
		}
		credentials, key, err := execution.ReadCredentials(c.CredentialFile)
		clear(key)
		if err != nil {
			return true, err
		}
		if c.Connection == nil || c.Connection.TenantID != credentials.TenantID {
			return true, ErrState
		}
		_, dbErr := os.Lstat(filepath.Join(c.StateDir, "journal.db"))
		_, anchorErr := os.Lstat(filepath.Join(c.StateDir, "recovery.anchor.json"))
		if os.IsNotExist(dbErr) && os.IsNotExist(anchorErr) {
			boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
			if err != nil || strings.TrimSpace(string(boot)) != credentials.BootID {
				return true, errors.New("original journal missing after boot change; retain enrollment and recover original evidence")
			}
			store, err := journal.OpenRecovery(context.Background(), c.StateDir, journal.Options{})
			if err != nil {
				return true, err
			}
			if err = store.Close(); err != nil {
				return true, err
			}
		} else if dbErr != nil || anchorErr != nil {
			return true, errors.New("original journal or anchor incomplete; startup enablement blocked")
		}
		return true, nil
	}
	if args[0] != "setup" {
		return true, diagnose(args[0])
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return true, errors.New("setup requires a protected interactive terminal")
	}
	channel, start, e := setupChildChannel()
	if e != nil {
		return true, e
	}
	if channel != nil {
		defer channel.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	// Repeated setup recovers its original public bindings rather than inviting a
	// new identity. A configured/active daemon must first be stopped explicitly.
	var previous attempt
	_ = readJSON("/etc/neticora-runnerd/setup/attempt.json", &previous)
	fmt.Println("Neticora Runnerd setup (Linux Standard; execution remains disabled)")
	var inputs setupInputs
	if start.Inputs != nil {
		inputs = *start.Inputs
	} else {
		inputs.Platform, e = prompt("Platform host API HTTPS URL: ", previous.PlatformURL)
		if e != nil {
			return true, e
		}
		inputs.Tenant, e = prompt("Canonical tenant ID: ", previous.TenantID)
		if e != nil {
			return true, e
		}
		inputs.Pool, e = prompt("Customer-host pool ID: ", previous.PoolID)
		if e != nil {
			return true, e
		}
		inputs.Endpoint, e = prompt("Customer-provisioned Docker endpoint: ", defaultValue(previous.RuntimeEndpoint, "unix:///run/docker.sock"))
		if e != nil {
			return true, e
		}
	}
	client, e := transport.New(inputs.Platform, 15*time.Second)
	if e != nil {
		return true, e
	}
	defer client.Close()
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return true, errors.New("cannot observe host boot identity")
	}
	o := Options{ConfigPath: configPath, SetupDir: "/etc/neticora-runnerd/setup", StateDir: "/var/lib/neticora-runnerd", CredentialPath: "/etc/neticora-runnerd/identity.json", PlatformURL: inputs.Platform, TenantID: inputs.Tenant, PoolID: inputs.Pool, RuntimeEndpoint: inputs.Endpoint, BootID: strings.TrimSpace(string(boot))}
	o.ReplaceToken = replaceToken
	o.Token = func() ([]byte, error) {
		return promptToken(os.Stdin, os.Stdout)
	}
	firstProbe := true
	o.Probe = func(ctx context.Context) (string, error) {
		mayAuthorize := firstProbe && start.MayAuthorize && channel != nil
		firstProbe = false
		engine, e := dockerengine.OpenReadOnly(inputs.Endpoint, "onboarding-observation", func() {})
		if e != nil {
			return "", e
		}
		defer engine.Close()
		endpoint, err := engine.Probe(ctx)
		if mayAuthorize && errors.Is(err, dockerengine.ErrPermission) {
			return "", errAuthorizeDocker
		}
		return endpoint, err
	}
	b, e := Setup(ctx, client, o)
	if errors.Is(e, errAuthorizeDocker) {
		// Exit before any enrollment effects. The root parent can authorize only
		// the fixed Docker group, then re-exec with freshly resolved account groups.
		return true, json.NewEncoder(channel).Encode(inputs)
	}
	if e != nil {
		return true, e
	}
	fmt.Printf("Enrollment verified.\nHost: %s\nTenant: %s\nPool: %s\nInstallation: %s\nDocker: available\nExecution qualification: separate\nExecution admission: disabled\n", b.Identity.HostId, b.TenantID, b.RunnerDeploymentID, b.InstallationID)
	return true, nil
}
func defaultValue(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
func prompt(label, fallback string) (string, error) {
	fmt.Print(label)
	if fallback != "" {
		fmt.Printf("[%s] ", fallback)
	}
	// Read one byte at a time: buffering must not consume the masked-token prompt.
	var data []byte
	var b [1]byte
	for len(data) < 2048 {
		n, e := os.Stdin.Read(b[:])
		if n > 0 {
			if b[0] == '\n' {
				s := strings.TrimSpace(string(data))
				return defaultValue(s, fallback), nil
			}
			data = append(data, b[0])
		}
		if e != nil {
			return "", errors.New("interactive input ended")
		}
	}
	return "", errors.New("interactive input too long")
}

func diagnose(command string) error {
	report := map[string]any{"version": execution.Version(), "productionApproved": false, "qualification": "separate", "admission": "unknown", "service": "unavailable"}
	defer func() { _ = json.NewEncoder(os.Stdout).Encode(report) }()
	raw, e := hostfs.ReadPrivate(configPath, config.MaxConfigBytes)
	if e != nil {
		report["installation"] = "configuration-required"
		return e
	}
	c, e := config.Parse(raw)
	if e != nil {
		return e
	}
	credentials, key, e := execution.ReadCredentials(c.CredentialFile)
	if e != nil {
		return e
	}
	defer clear(key)
	credentials, e = connectionrecovery.Load(c, credentials)
	if e != nil {
		return e
	}
	report["installation"] = "enrolled"
	report["tenantId"] = credentials.TenantID
	report["hostId"] = credentials.Identity.HostId
	report["installationId"] = credentials.InstallationID
	report["sessionEpoch"] = credentials.Identity.SessionEpoch
	if c.Connection != nil {
		report["poolId"] = c.Connection.RunnerDeploymentID
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", "/run/neticora-runnerd/control.sock")
	}}
	defer tr.CloseIdleConnections()
	h := http.Client{Transport: tr, Timeout: 3 * time.Second}
	response, e := h.Get("http://localhost/" + command)
	if e == nil {
		defer response.Body.Close()
		data, _ := io.ReadAll(io.LimitReader(response.Body, 65536))
		var status map[string]any
		if response.StatusCode == 200 && json.Unmarshal(data, &status) == nil {
			report["service"] = "running"
			report["daemon"] = status
		}
	}
	if command == "status" {
		return nil
	}
	verify := exec.Command("/usr/bin/dpkg", "--verify", "neticora-runnerd")
	verification, err := verify.Output()
	if err != nil || len(verification) != 0 {
		return errors.New("installed package integrity check failed")
	}
	report["packageIntegrity"] = "verified-against-installed-metadata"
	identity, err := resolveServiceIdentity()
	if err != nil {
		return err
	}
	if err = identity.verifyCurrent(); err != nil {
		return err
	}
	report["serviceIdentity"] = "configured-uid-gid-groups-verified"
	state, err := hostfs.OpenState(c.StateDir)
	if err != nil {
		return err
	}
	state.Close()
	report["statePermissions"] = "verified"
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	engine, e := dockerengine.OpenReadOnly(c.RuntimeEndpoint, credentials.InstallationID, func() {})
	if e != nil {
		return fmt.Errorf("Docker observation failed: %w", e)
	}
	defer engine.Close()
	endpoint, e := engine.Probe(ctx)
	if e != nil {
		return fmt.Errorf("Docker observation failed: %w", e)
	}
	if endpoint != credentials.EndpointIdentity {
		return dockerengine.ErrContinuity
	}
	report["docker"] = "original-peer-verified"
	client, e := transport.New(c.ControlPlaneURL, c.Timeout())
	if e != nil {
		return e
	}
	defer client.Close()
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return errors.New("host boot identity unavailable")
	}
	access, e := Authenticate(ctx, client, key, credentials.Identity, strings.TrimSpace(string(boot)))
	if e != nil {
		return e
	}
	b, e := client.Installation(ctx, access)
	if e != nil {
		return e
	}
	if c.Connection == nil || b.Identity != credentials.Identity || b.InstallationID != credentials.InstallationID || b.TenantID != c.Connection.TenantID || b.RunnerDeploymentID != c.Connection.RunnerDeploymentID || b.EnrollmentRequestID != c.Connection.EnrollmentRequestID || b.PublicKeyFingerprint != c.Connection.PublicKeyFingerprint {
		return ErrState
	}
	report["platform"] = "authenticated-binding-verified"
	return nil
}
