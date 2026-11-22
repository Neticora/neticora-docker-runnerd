//go:build linux

package onboarding

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"reflect"
	"testing"
)

func TestServiceIdentityUsesOnlyConfiguredGroups(t *testing.T) {
	identity, err := identityForAccount(&user.User{Username: serviceAccount, Uid: "982", Gid: "982"}, []string{"982", "989", "989", "998"})
	if err != nil || identity.uid != 982 || identity.gid != 982 || !reflect.DeepEqual(identity.groups, []uint32{989, 998}) {
		t.Fatalf("configured service identity: %+v %v", identity, err)
	}
	credential := identity.credential()
	if credential.NoSetGroups || !reflect.DeepEqual(credential.Groups, []uint32{989, 998}) {
		t.Fatal("must explicitly initialize target groups before dropping privileges")
	}
	if err = identity.verify(982, 982, 982, 982, []int{998, 982, 989}); err != nil {
		t.Fatal(err)
	}
	for _, actual := range [][]int{{}, {989}, {989, 998, 0}, {989, 998, 27}} {
		if err = identity.verify(982, 982, 982, 982, actual); !errors.Is(err, ErrGroupsInactive) {
			t.Fatalf("missing/stale/inherited groups accepted: %v %v", actual, err)
		}
	}
	for _, ids := range [][4]int{{0, 982, 982, 982}, {982, 0, 982, 982}, {982, 982, 0, 982}, {982, 982, 982, 0}} {
		if !errors.Is(identity.verify(ids[0], ids[1], ids[2], ids[3], []int{989, 998}), ErrServiceIdentity) {
			t.Fatalf("unexpected process identity accepted: %v", ids)
		}
	}
}

func TestServiceIdentityRejectsRootAndMalformedAccounts(t *testing.T) {
	for _, account := range []*user.User{nil, {Username: "root", Uid: "0", Gid: "0"},
		{Username: serviceAccount, Uid: "0", Gid: "982"}, {Username: serviceAccount, Uid: "982", Gid: "0"},
		{Username: serviceAccount, Uid: "-1", Gid: "982"}, {Username: serviceAccount, Uid: "982", Gid: "4294967295"}} {
		if _, err := identityForAccount(account, nil); !errors.Is(err, ErrServiceIdentity) {
			t.Fatalf("unsafe account accepted: %+v %v", account, err)
		}
	}
	for _, groups := range [][]string{{"0"}, {"bad"}, {"4294967296"}} {
		if _, err := identityForAccount(&user.User{Username: serviceAccount, Uid: "982", Gid: "982"}, groups); !errors.Is(err, ErrServiceIdentity) {
			t.Fatalf("unsafe groups accepted: %v %v", groups, err)
		}
	}
}

func TestServiceIdentityExecUsesKernelCredentials(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root in the disposable qualification VM")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	identity := serviceIdentity{uid: 65534, gid: 65534, groups: []uint32{65532, 65533}}
	command := exec.Command(binary, "-test.run=^TestServiceIdentityExecHelper$")
	command.Env = []string{"RUNNERD_IDENTITY_EXEC_HELPER=1"}
	command.SysProcAttr = serviceProcessAttributes(identity)
	data, err := command.Output()
	if err != nil {
		t.Fatalf("service exec: %s %v", data, err)
	}
	var actual struct {
		UID, EUID, GID, EGID int
		Groups               []int
	}
	if json.Unmarshal(data, &actual) != nil || identity.verify(actual.UID, actual.EUID, actual.GID, actual.EGID, actual.Groups) != nil {
		t.Fatalf("kernel credential mismatch: %s", data)
	}
	t.Logf("kernel credential proof: %s", data)
}

func TestServiceIdentityExecHelper(t *testing.T) {
	if os.Getenv("RUNNERD_IDENTITY_EXEC_HELPER") != "1" {
		t.Skip("subprocess entry")
	}
	groups, err := os.Getgroups()
	if err != nil {
		os.Exit(2)
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"UID": os.Getuid(), "EUID": os.Geteuid(), "GID": os.Getgid(), "EGID": os.Getegid(), "Groups": groups})
	os.Exit(0)
}
