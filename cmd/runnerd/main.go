package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Neticora/neticora-docker-runnerd/internal/config"
	"github.com/Neticora/neticora-docker-runnerd/internal/execution"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/internal/onboarding"
	"github.com/Neticora/neticora-docker-runnerd/internal/service"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if handled, err := onboarding.Command(os.Args[1:]); handled {
		return err
	}
	version := flag.Bool("version", false, "print actual executable version")
	file := flag.String("config", "/etc/neticora-runnerd/config.json", "protected configuration file")
	recovery := flag.String("recovery", "", "operator recovery: diagnose, inspect or apply; daemon must be stopped")
	recoveryInput := flag.String("recovery-input", "", "protected challenge or signed approval JSON")
	recoveryPublicKey := flag.String("recovery-public-key", "", "protected independent operator public key PEM (apply only)")
	socket := flag.String("socket", "/run/neticora-runnerd/control.sock", "local control socket")
	flag.Parse()
	if *version {
		fmt.Println(execution.Version())
		return nil
	}
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	raw, err := hostfs.ReadPrivate(*file, config.MaxConfigBytes)
	if err != nil {
		return err
	}
	c, err := config.Parse(raw)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *recovery != "" {
		result, err := execution.AdministrativePeerRecovery(ctx, c, *recovery, *recoveryInput, *recoveryPublicKey)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(append(result, '\n'))
		return err
	}
	return service.Run(ctx, c, *socket)
}
