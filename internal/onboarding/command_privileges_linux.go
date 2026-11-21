//go:build linux

package onboarding

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const setupChannelEnv = "_NETICORA_RUNNERD_SETUP_CHANNEL"
const maxSetupFrame = 12 << 10

var errAuthorizeDocker = errors.New("Docker access requires root-parent authorization")

// This channel carries only public prompt answers. Tokens, keys and enrollment
// responses never leave the service-identity process through this channel.
type setupInputs struct {
	Platform string `json:"platform"`
	Tenant   string `json:"tenant"`
	Pool     string `json:"pool"`
	Endpoint string `json:"endpoint"`
}

type setupStart struct {
	Inputs       *setupInputs `json:"inputs,omitempty"`
	MayAuthorize bool         `json:"mayAuthorize"`
}

func readSetupFrame(reader io.Reader, value any) error {
	decoder := json.NewDecoder(io.LimitReader(reader, maxSetupFrame))
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}

func setupChildChannel() (net.Conn, setupStart, error) {
	var start setupStart
	if os.Getenv(setupChannelEnv) == "" {
		return nil, start, nil
	}
	if os.Getenv(setupChannelEnv) != "3" {
		return nil, start, ErrServiceIdentity
	}
	file := os.NewFile(3, "setup-parent")
	defer file.Close()
	// The inherited private socketpair must have been created by root. A
	// standalone service-account invocation cannot manufacture a root parent.
	cred, err := unix.GetsockoptUcred(3, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil || cred.Uid != 0 || int(cred.Pid) != os.Getppid() {
		return nil, start, ErrServiceIdentity
	}
	conn, err := net.FileConn(file)
	if err != nil {
		return nil, start, ErrServiceIdentity
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err = readSetupFrame(conn, &start); err != nil {
		conn.Close()
		return nil, start, ErrServiceIdentity
	}
	_ = conn.SetReadDeadline(time.Time{})
	return conn, start, nil
}

func runServiceCommand(args []string, identity serviceIdentity, start setupStart) (*setupInputs, error) {
	binary, err := os.Executable()
	if err != nil {
		return nil, err
	}
	command := exec.Command(binary, args...)
	command.SysProcAttr = serviceProcessAttributes(identity)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	var parent net.Conn
	var childFile *os.File
	if args[0] == "setup" {
		pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return nil, ErrServiceIdentity
		}
		parentFile := os.NewFile(uintptr(pair[0]), "setup-service")
		childFile = os.NewFile(uintptr(pair[1]), "setup-root")
		defer childFile.Close()
		parent, err = net.FileConn(parentFile)
		parentFile.Close()
		if err != nil {
			return nil, ErrServiceIdentity
		}
		defer parent.Close()
		_ = parent.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err = json.NewEncoder(parent).Encode(start); err != nil {
			return nil, ErrServiceIdentity
		}
		command.ExtraFiles = []*os.File{childFile}
		command.Env = append(command.Env, setupChannelEnv+"=3")
	}
	if err = command.Start(); err != nil {
		return nil, ErrServiceIdentity
	}
	if childFile != nil {
		childFile.Close()
	}
	err = command.Wait()
	if err != nil {
		return nil, errors.New("command failed; original installation state retained")
	}
	if parent == nil {
		return nil, nil
	}
	_ = parent.SetReadDeadline(time.Now().Add(time.Second))
	var request setupInputs
	if err = readSetupFrame(parent, &request); errors.Is(err, io.EOF) {
		return nil, nil
	} else if err != nil || !start.MayAuthorize || request.Endpoint == "" {
		return nil, ErrAuthorizationFailed
	}
	return &request, nil
}

func commandAsService(args []string, identity serviceIdentity) error {
	request, err := runServiceCommand(args, identity, setupStart{MayAuthorize: true})
	if err != nil {
		return err
	}
	if request != nil {
		if err = authorizeDockerAccess(request.Endpoint); err != nil {
			return err
		}
		fresh, err := resolveServiceIdentity()
		if err != nil {
			return err
		}
		if fresh.uid != identity.uid || fresh.gid != identity.gid {
			return ErrServiceIdentity
		}
		identity = fresh
		fmt.Println("Docker access authorized. Refreshing the service identity and continuing the original setup.")
		if _, err = runServiceCommand(args, identity, setupStart{Inputs: request}); err != nil {
			return err
		}
	}
	if args[0] == "enable-startup" {
		return exec.Command("/usr/bin/systemctl", "enable", "neticora-runnerd.service").Run()
	}
	if args[0] == "setup" {
		answer, err := prompt("Start Runnerd now and enable startup on boot? [y/N]: ", "")
		if err != nil {
			return err
		}
		if strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes") {
			// start does not restart an already running service. Setup itself
			// retains the original instance lock and rejects active execution state.
			start := exec.Command("/usr/bin/systemctl", "enable", "--now", "neticora-runnerd.service")
			start.Stdout, start.Stderr = os.Stdout, os.Stderr
			if start.Run() != nil {
				return errors.New("service did not start; use doctor and journalctl")
			}
		}
	}
	return nil
}
