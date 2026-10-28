// runnerd-verify is an offline foundation artifact verifier. It does not install
// artifacts or authorize production execution. Bootstrap the verifier itself
// through an independently trusted installer, never through the artifact it checks.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Neticora/neticora-docker-runnerd/internal/updatetrust"
)

func main() {
	bootstrap := flag.String("bootstrap", "/etc/neticora-runnerd/update-trust/bootstrap.json", "independently provisioned private bootstrap")
	pin := flag.String("bootstrap-sha256", "", "independently obtained SHA-256 of exact bootstrap bytes")
	state := flag.String("state", "/var/lib/neticora-runnerd-update-trust", "protected persistent anti-rollback state")
	bundle := flag.String("bundle", "", "local offline update directory")
	source := flag.String("source", "", "independently reviewed full source commit")
	initialize := flag.Bool("initialize-state", false, "explicitly initialize a new trust store; never resets existing state")
	renew := flag.Bool("renew-bootstrap", false, "explicit independently pinned bootstrap renewal preserving state")
	newBootstrap := flag.String("new-bootstrap", "", "new protected bootstrap for explicit renewal")
	newPin := flag.String("new-bootstrap-sha256", "", "independently obtained new bootstrap SHA-256")
	qualification := flag.Bool("qualification-only", false, "use only explicitly provisioned local-qualification trust; no release authority")
	flag.Parse()
	if *initialize && *renew {
		fmt.Fprintln(os.Stderr, "choose one trust administration operation")
		os.Exit(1)
	}
	if flag.NArg() != 0 || (os.Geteuid() != 0 && !*qualification) {
		fmt.Fprintln(os.Stderr, "root required for installed trust; local qualification requires its explicit flag")
		os.Exit(1)
	}
	if *initialize {
		if err := updatetrust.Initialize(*bootstrap, *pin, *state, *qualification); err != nil {
			fmt.Fprintln(os.Stderr, "trust initialization rejected")
			os.Exit(1)
		}
		fmt.Println("trust state initialized; no artifact installed")
		return
	}
	if *renew {
		if err := updatetrust.Reanchor(*bootstrap, *pin, *newBootstrap, *newPin, *state, *qualification); err != nil {
			fmt.Fprintln(os.Stderr, "bootstrap renewal rejected")
			os.Exit(1)
		}
		fmt.Println("bootstrap renewed; revocation and release rollback state preserved")
		return
	}
	result, err := updatetrust.Verify(*bootstrap, *pin, *state, *bundle, *source, *qualification)
	if err != nil {
		// Do not print attacker-controlled paths, certificate subjects or payloads.
		fmt.Fprintln(os.Stderr, "offline update verification rejected")
		os.Exit(1)
	}
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		os.Exit(1)
	}
}
