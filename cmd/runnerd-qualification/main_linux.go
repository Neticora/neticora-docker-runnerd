//go:build linux && runnerd_qualification

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/execution"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
	"github.com/Neticora/neticora-docker-runnerd/internal/provision"
	"github.com/Neticora/neticora-docker-runnerd/internal/qualfixture"
	"github.com/Neticora/neticora-docker-runnerd/internal/standardlinux"
)

func run() error {
	role := flag.String("role", "", "controller, observer, fixture or sign-lab")
	file := flag.String("config", "", "protected configuration path")
	bindingFile := flag.String("binding", "", "independently approved protected lab binding")
	pin := flag.String("authority-pin", "", "independently pinned Ed25519 public DER SHA256")
	control := flag.String("control", "", "private controller barrier directory")
	phase := flag.String("phase", "none", "explicit qualification fault phase")
	listen := flag.String("listen", "", "fixture private IP:port")
	certFile := flag.String("tls-cert", "", "protected fixture TLS certificate")
	keyFile := flag.String("tls-key", "", "protected fixture TLS private key; workstation only")
	state := flag.String("state", "", "protected durable fixture state directory")
	output := flag.String("output", "", "fresh signed lab envelope output")
	caseID := flag.String("case", "", "exact lab case ID")
	endpoint := flag.String("endpoint", "", "observed Docker endpoint identity for lab identity initialization")
	trial := flag.String("trial", "", "fresh campaign trial ID")
	bootstrapFile := flag.String("bootstrap-file", "", "protected workstation-only bootstrap input")
	bootstrapExpiry := flag.String("bootstrap-expires-at", "", "actual bootstrap expiry")
	previousState := flag.String("previous-state", "", "prior closed trial fixture state; inventory continuity")
	executionID := flag.String("execution-id", "", "exact execution to export evidence for")
	flag.Parse()
	if flag.NArg() != 0 {
		return katalinux.ErrQualification
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if *role == "prepare-trial" {
		raw, err := hostfs.ReadPrivate(*file, 131072)
		if err != nil {
			return err
		}
		var base qualfixture.Config
		if json.Unmarshal(raw, &base) != nil {
			return qualfixture.ErrFixture
		}
		prepared, err := qualfixture.PrepareTrial(base, *trial, *bootstrapFile, *bootstrapExpiry, *previousState, *output)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"executionId": prepared.Start.Spec.ExecutionId, "trial": *trial})
	}
	if *role == "verify-result" {
		raw, err := hostfs.ReadPrivate(*file, 1<<20)
		if err != nil {
			return err
		}
		var input qualfixture.ResultInput
		if json.Unmarshal(raw, &input) != nil {
			return qualfixture.ErrFixture
		}
		if err = qualfixture.VerifyResult(input, *pin); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"passed": true, "scope": "isolated-fixture-controller-cleanup", "productionQualified": false, "providerJobVerified": false})
	}
	if *role == "check-identity" {
		credentials, key, err := execution.ReadCredentials(*file)
		if err != nil {
			return err
		}
		defer clear(key)
		der, _ := x509.MarshalPKIXPublicKey(key.Public())
		public := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
		sum := sha256.Sum256(public)
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"hostId": credentials.Identity.HostId, "installationId": credentials.InstallationID, "bootId": credentials.BootID, "hostPublicKeySha256": hex.EncodeToString(sum[:])})
	}
	if *role == "verify-plan" {
		raw, err := hostfs.ReadPrivate(*file, 131072)
		if err != nil {
			return err
		}
		var envelope katalinux.LabEnvelope
		if json.Unmarshal(raw, &envelope) != nil {
			return katalinux.ErrQualification
		}
		original, _ := protocol.CanonicalizeJSON(raw)
		normalized, _ := json.Marshal(envelope)
		normalized, _ = protocol.CanonicalizeJSON(normalized)
		if len(original) == 0 || string(original) != string(normalized) {
			return katalinux.ErrQualification
		}
		raw, err = hostfs.ReadPrivate(*bindingFile, 131072)
		if err != nil {
			return err
		}
		bundle, err := provision.Parse(raw)
		if err != nil {
			return err
		}
		public, err := hostfs.ReadPrivate(*keyFile, 16384)
		if err != nil {
			return err
		}
		x := bundle.Daemon.Execution
		if err = qualfixture.ValidatePlanBundle(envelope, bundle); err != nil {
			return err
		}
		return katalinux.ValidateLabPlan(envelope, public, *pin, x.Kata.EvidenceDirectory, bundle.Daemon.StateDir, standardlinux.Settings{ImageRepository: x.ImageRepository, NetworkID: x.NetworkID, BootstrapRoot: x.BootstrapRoot, RunnerUID: bundle.Observer.ServiceUID, PidsLimit: x.PidsLimit})
	}
	if *role == "identity" {
		metadata, err := qualfixture.InitIdentity(*caseID, *endpoint, *output)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(metadata)
	}
	if *role == "inspect" || *role == "prepare" {
		raw, err := hostfs.ReadPrivate(*file, 131072)
		if err != nil {
			return err
		}
		if *role == "inspect" {
			var request qualfixture.TupleRequest
			if json.Unmarshal(raw, &request) != nil {
				return katalinux.ErrQualification
			}
			plan, err := qualfixture.InspectTuple(ctx, request)
			if err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(plan)
		}
		var spec qualfixture.PrepareSpec
		if json.Unmarshal(raw, &spec) != nil {
			return katalinux.ErrQualification
		}
		receipt, err := qualfixture.Prepare(spec, *output)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(receipt)
	}
	if *role == "sign-lab" {
		if !filepath.IsAbs(*output) || filepath.Clean(*output) != *output || hostfs.CheckAncestors(filepath.Dir(*output)) != nil {
			return katalinux.ErrQualification
		}
		raw, err := hostfs.ReadPrivate(*file, 131072)
		if err != nil {
			return err
		}
		var envelope katalinux.LabEnvelope
		if json.Unmarshal(raw, &envelope) != nil {
			return katalinux.ErrQualification
		}
		secret, err := io.ReadAll(io.LimitReader(os.Stdin, 16385))
		if err != nil || len(secret) > 16384 {
			return katalinux.ErrQualification
		}
		defer clear(secret)
		block, rest := pem.Decode(secret)
		if block == nil || len(rest) != 0 {
			return katalinux.ErrQualification
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		key, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return katalinux.ErrQualification
		}
		defer clear(key)
		der, _ := x509.MarshalPKIXPublicKey(key.Public())
		sum := sha256.Sum256(der)
		if hex.EncodeToString(sum[:]) != *pin {
			return katalinux.ErrQualification
		}
		signed, err := katalinux.SignLabEnvelope(envelope, key)
		if err != nil {
			return err
		}
		data, _ := json.Marshal(signed)
		f, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, err = f.Write(append(data, '\n'))
		if err == nil {
			err = f.Sync()
		}
		err = errors.Join(err, f.Close())
		if err != nil {
			return err
		}
		parent, err := os.Open(filepath.Dir(*output))
		if err != nil {
			return err
		}
		defer parent.Close()
		return parent.Sync()
	}
	if *role == "fixture" {
		var disk syscall.Statfs_t
		if syscall.Statfs(*state, &disk) != nil || (disk.Type != 0xef53 && disk.Type != 0x58465342 && disk.Type != 0x9123683e) {
			return qualfixture.ErrFixture
		}
		host, _, err := net.SplitHostPort(*listen)
		if err != nil {
			return err
		}
		ip, err := netip.ParseAddr(host)
		if err != nil || (!ip.IsLoopback() && !ip.IsPrivate()) {
			return katalinux.ErrQualification
		}
		raw, err := hostfs.ReadPrivate(*file, 131072)
		if err != nil {
			return err
		}
		fixture, err := qualfixture.New(raw, *state)
		if err != nil {
			return err
		}
		defer fixture.Close()
		cert, err := hostfs.ReadPrivate(*certFile, 16384)
		if err != nil {
			return err
		}
		key, err := hostfs.ReadPrivate(*keyFile, 16384)
		if err != nil {
			return err
		}
		defer clear(key)
		pair, err := tls.X509KeyPair(cert, key)
		if err != nil {
			return err
		}
		listener, err := net.Listen("tcp", *listen)
		if err != nil {
			return err
		}
		defer listener.Close()
		server := &http.Server{Handler: fixture, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, MaxHeaderBytes: 16384, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}}
		go func() {
			<-ctx.Done()
			stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			server.Shutdown(stop)
		}()
		err = server.Serve(tls.NewListener(listener, server.TLSConfig))
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
	if *role == "controller" {
		return execution.RunKataQualification(ctx, *file, *bindingFile, *pin, *control, *phase, *executionID)
	}
	if *role != "observer" {
		return katalinux.ErrQualification
	}
	raw, err := hostfs.ReadPrivate(*bindingFile, 65536)
	if err != nil {
		return err
	}
	var binding katalinux.LabBinding
	if json.Unmarshal(raw, &binding) != nil {
		return katalinux.ErrQualification
	}
	return katalinux.ServeQualificationObserver(ctx, *file, *pin, binding)
}
func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "Qualification harness refused or stopped; retain state and evidence; no production qualification granted")
		os.Exit(1)
	}
}
