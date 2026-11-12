//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Neticora/neticora-docker-runnerd/internal/broker"
)

func main() {
	file := flag.String("config", "/etc/neticora-runnerd-broker/config.json", "root-private broker configuration")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "Unexpected broker arguments")
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if broker.Serve(ctx, *file) != nil {
		fmt.Fprintln(os.Stderr, "Broker refused configuration or service lifecycle; preserve state for reconciliation")
		os.Exit(1)
	}
}
