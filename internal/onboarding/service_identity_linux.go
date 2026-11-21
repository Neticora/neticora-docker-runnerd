//go:build linux

package onboarding

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"slices"
	"strconv"
	"syscall"
)

const serviceAccount = "neticora-runnerd"

var (
	ErrServiceIdentity     = errors.New("SERVICE_IDENTITY_INVALID: cannot establish the dedicated Runnerd service identity")
	ErrGroupsInactive      = errors.New("DOCKER_GROUP_MEMBERSHIP_INACTIVE: process groups differ from the service account's configured groups; start a fresh setup process with sudo; do not restart an active Runnerd service with unresolved obligations")
	ErrAuthorizationFailed = errors.New("DOCKER_AUTHORIZATION_FAILED: Docker access authorization failed; original enrollment retained")
)

type serviceIdentity struct {
	uid, gid uint32
	groups   []uint32
}

func identityForAccount(account *user.User, groupIDs []string) (serviceIdentity, error) {
	var identity serviceIdentity
	parse := func(value string) (uint32, error) {
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil || n == 0 || n == 1<<32-1 {
			return 0, ErrServiceIdentity
		}
		return uint32(n), nil
	}
	if account == nil || account.Username != serviceAccount {
		return identity, ErrServiceIdentity
	}
	var err error
	if identity.uid, err = parse(account.Uid); err != nil {
		return identity, err
	}
	if identity.gid, err = parse(account.Gid); err != nil {
		return identity, err
	}
	for _, raw := range groupIDs {
		group, err := parse(raw)
		if err != nil {
			return serviceIdentity{}, err
		}
		if group != identity.gid {
			identity.groups = append(identity.groups, group)
		}
	}
	slices.Sort(identity.groups)
	identity.groups = slices.Compact(identity.groups)
	return identity, nil
}

func resolveServiceIdentity() (serviceIdentity, error) {
	account, err := user.Lookup(serviceAccount)
	if err != nil {
		return serviceIdentity{}, fmt.Errorf("%w; install the Debian package first", ErrServiceIdentity)
	}
	groups, err := account.GroupIds()
	if err != nil {
		return serviceIdentity{}, fmt.Errorf("%w: cannot resolve account groups", ErrServiceIdentity)
	}
	return identityForAccount(account, groups)
}

func (identity serviceIdentity) credential() *syscall.Credential {
	// Supplying the complete target group list causes setgroups before setgid
	// and setuid in Go's Linux fork/exec path. No caller groups are inherited.
	return &syscall.Credential{Uid: identity.uid, Gid: identity.gid, Groups: append([]uint32{}, identity.groups...)}
}

func serviceProcessAttributes(identity serviceIdentity) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Credential: identity.credential()}
}

func (identity serviceIdentity) verify(uid, euid, gid, egid int, groups []int) error {
	if uid != int(identity.uid) || euid != int(identity.uid) || gid != int(identity.gid) || egid != int(identity.gid) {
		return ErrServiceIdentity
	}
	actual := make([]uint32, 0, len(groups))
	for _, group := range groups {
		if group < 0 {
			return ErrServiceIdentity
		}
		if uint32(group) != identity.gid {
			actual = append(actual, uint32(group))
		}
	}
	slices.Sort(actual)
	actual = slices.Compact(actual)
	if !slices.Equal(actual, identity.groups) {
		return ErrGroupsInactive
	}
	return nil
}

func (identity serviceIdentity) verifyCurrent() error {
	groups, err := os.Getgroups()
	if err != nil {
		return ErrServiceIdentity
	}
	return identity.verify(os.Getuid(), os.Geteuid(), os.Getgid(), os.Getegid(), groups)
}
