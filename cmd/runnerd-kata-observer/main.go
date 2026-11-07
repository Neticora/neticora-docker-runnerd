package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Neticora/neticora-docker-runnerd/internal/katalinux"
)

func main() {
	file := flag.String("config", "/etc/neticora-runnerd-kata-observer/config.json", "root-owned private observer config")
	profile := flag.String("profile", "", "exact signed profile identity for storage reconciliation")
	approval := flag.String("storage-reconcile", "", "root-private signed cleanup-only storage reconciliation artifact; stop service and keep it stopped until this command returns; signed by the offline Kata authority")
	flag.Parse()
	if *approval != "" {
		if flag.NArg() != 0 || *profile == "" || katalinux.InstallStorageReconciliation(*file, *profile, *approval) != nil {
			fmt.Fprintln(os.Stderr, "Storage reconciliation refused; host remains fenced")
			os.Exit(1)
		}
		fmt.Println("Signed storage reconciliation recorded; admission remains fenced")
		return
	}
	if *profile != "" {
		fmt.Fprintln(os.Stderr, "Profile flag requires a storage reconciliation artifact")
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "Unexpected observer arguments")
		os.Exit(1)
	}
	if err := katalinux.ServeObserver(ctx, *file); err != nil {
		if errors.Is(err, katalinux.ErrObserverLifecycleBusy) {
			fmt.Fprintln(os.Stderr, "Observer lifecycle locked; start the service explicitly after maintenance")
			os.Exit(75)
		}
		fmt.Fprintln(os.Stderr, "Kata observer refused configuration or operation")
		os.Exit(1)
	}
}
