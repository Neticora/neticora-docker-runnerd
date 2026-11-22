//go:build linux

package onboarding

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"
)

type dockerSocketAuthorization struct {
	path  string
	stat  syscall.Stat_t
	group uint32
}

func inspectDockerAuthorization(endpoint string) (dockerSocketAuthorization, error) {
	var socket dockerSocketAuthorization
	if err := dockerengine.ValidateEndpoint(endpoint); err != nil {
		return socket, err
	}
	// ValidateEndpoint accepts only a clean absolute local Unix path.
	parsed, _ := url.Parse(endpoint)
	socket.path = parsed.Path
	info, err := os.Lstat(socket.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return socket, dockerengine.ErrSocketInaccessible
		}
		return socket, fmt.Errorf("%w: cannot inspect selected socket", ErrAuthorizationFailed)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	group, groupErr := user.LookupGroup("docker")
	if !ok || groupErr != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0660 || stat.Uid != 0 {
		return socket, fmt.Errorf("%w; automatic authorization requires a root:docker Unix socket with mode 0660; ask the host administrator to review the existing endpoint", dockerengine.ErrUnsupported)
	}
	gid, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil || gid == 0 || gid != uint64(stat.Gid) {
		return socket, fmt.Errorf("%w; socket group must match the local docker group", dockerengine.ErrUnsupported)
	}
	socket.stat, socket.group = *stat, uint32(gid)
	return socket, nil
}

func sameAuthorizationSocket(before, after dockerSocketAuthorization) bool {
	return before.path == after.path && before.group == after.group &&
		before.stat.Dev == after.stat.Dev && before.stat.Ino == after.stat.Ino &&
		before.stat.Mode == after.stat.Mode && before.stat.Uid == after.stat.Uid && before.stat.Gid == after.stat.Gid
}

func (identity serviceIdentity) hasGroup(group uint32) bool {
	if identity.gid == group {
		return true
	}
	for _, configured := range identity.groups {
		if configured == group {
			return true
		}
	}
	return false
}

// approveDockerAccess never opens Docker as root. The service child already
// failed its read-only probe; the root parent only inspects access metadata and
// performs this one fixed, explicitly approved account-management operation.
func approveDockerAccess(endpoint string, confirm func() (bool, error), grant func() error,
	resolve func() (serviceIdentity, error), inspect func(string) (dockerSocketAuthorization, error)) error {
	before, err := inspect(endpoint)
	if err != nil {
		return err
	}
	identity, err := resolve()
	if err != nil {
		return err
	}
	if identity.hasGroup(before.group) {
		return fmt.Errorf("%w: account already belongs to docker; inspect socket ACLs and the effective process identity instead of changing permissions", ErrAuthorizationFailed)
	}
	approved, err := confirm()
	if err != nil {
		return err
	}
	if !approved {
		return fmt.Errorf("%w; authorization declined; no enrollment token requested or consumed", dockerengine.ErrPermission)
	}
	after, err := inspect(endpoint)
	if err != nil {
		return err
	}
	if !sameAuthorizationSocket(before, after) {
		return dockerengine.ErrContinuity
	}
	current, err := resolve()
	if err != nil || current.uid != identity.uid || current.gid != identity.gid {
		return ErrServiceIdentity
	}
	// Another administrator may have granted access during the prompt.
	if !current.hasGroup(before.group) {
		if err = grant(); err != nil {
			return err
		}
	}
	current, err = resolve()
	if err != nil || current.uid != identity.uid || current.gid != identity.gid || !current.hasGroup(before.group) {
		return ErrAuthorizationFailed
	}
	return nil
}

func authorizeDockerAccess(endpoint string) error {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return fmt.Errorf("%w: run setup with sudo", ErrAuthorizationFailed)
	}
	return approveDockerAccess(endpoint, func() (bool, error) {
		fmt.Printf("\nDocker socket: %s\nRunnerd account: %s\nDocker access: Authorization required\n\nDocker group membership provides root-equivalent access to this host.\nOnly the Runnerd service account will be added; Docker configuration and socket permissions stay unchanged.\n\n[1] Authorize and continue\n[2] Cancel\n", endpoint, serviceAccount)
		selection, err := prompt("Selection [2]: ", "2")
		return selection == "1", err
	}, func() error {
		command := exec.Command("/usr/sbin/usermod", "-a", "-G", "docker", "--", serviceAccount)
		command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
		var diagnostic bytes.Buffer
		command.Stderr = &diagnostic
		if err := command.Run(); err != nil {
			// The fixed command receives no credentials or caller-controlled values.
			message := strings.TrimSpace(diagnostic.String())
			if len(message) > 1024 {
				message = message[:1024]
			}
			return fmt.Errorf("%w: usermod: %v %s", ErrAuthorizationFailed, err, message)
		}
		return nil
	}, resolveServiceIdentity, inspectDockerAuthorization)
}
