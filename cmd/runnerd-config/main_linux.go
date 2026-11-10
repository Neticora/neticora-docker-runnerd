//go:build linux

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
	"github.com/Neticora/neticora-docker-runnerd/internal/provision"
)

func run() error {
	input := flag.String("input", "", "protected bundle input JSON")
	output := flag.String("output", "", "fresh absolute private output directory")
	flag.Parse()
	if flag.NArg() != 0 || *input == "" || *output == "" {
		return provision.ErrProvision
	}
	raw, err := hostfs.ReadPrivate(*input, 131072)
	if err != nil {
		return err
	}
	b, err := provision.Parse(raw)
	if err != nil {
		return err
	}
	receipt, err := provision.Write(*output, b)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(receipt)
}
func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "Configuration generation rejected; existing files and services were not changed")
		os.Exit(1)
	}
}
