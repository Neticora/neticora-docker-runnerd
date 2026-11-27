//go:build linux

package dockerengine

import "testing"

func TestKataStartupConfigurationCannotBeSubstituted(t *testing.T) {
	valid := []byte(`{"data-root":"/qualified/docker","runtimes":{"kata":{"runtimeType":"/pinned/shim","options":{"ConfigPath":"/pinned/kata.toml"}}}}`)
	if !matchingKataStartupConfig(valid, "kata", "/pinned/shim", "/pinned/kata.toml") {
		t.Fatal("valid pinned runtime refused")
	}
	for _, raw := range []string{
		`{"runtimes":{"kata":{"runtimeType":"runc","options":{"ConfigPath":"/pinned/kata.toml"}}}}`,
		`{"runtimes":{"kata":{"runtimeType":"/pinned/shim","options":{"ConfigPath":"/other.toml"}}}}`,
		`{"runtimes":{"kata":{"runtimeType":"/pinned/shim","path":"/substitute","options":{"ConfigPath":"/pinned/kata.toml"}}}}`,
		`{"runtimes":{"kata":{"runtimeType":"runc","runtimeType":"/pinned/shim","options":{"ConfigPath":"/pinned/kata.toml"}}}}`,
		`{"runtimes":{"kata":{"runtimeType":"/pinned/shim","options":{"ConfigPath":"/pinned/kata.toml","Other":"unreviewed"}}}}`,
	} {
		if matchingKataStartupConfig([]byte(raw), "kata", "/pinned/shim", "/pinned/kata.toml") {
			t.Fatal("substituted configuration accepted", raw)
		}
	}
}
func TestKataConfigBindingRejectsCommandLineOverrides(t *testing.T) {
	for _, args := range [][]string{{"dockerd", "--config-file", "/pinned/docker.json"}, {"dockerd", "--config-file=/pinned/docker.json"}} {
		if !exactDaemonConfigArgument(args, "/pinned/docker.json") {
			t.Fatal("valid startup rejected")
		}
	}
	for _, args := range [][]string{{"dockerd"}, {"dockerd", "--config-file", "/other.json"}, {"dockerd", "--config-file=/pinned/docker.json", "--add-runtime=kata=/other"}, {"dockerd", "--config-file=/pinned/docker.json", "--config-file=/other"}} {
		if exactDaemonConfigArgument(args, "/pinned/docker.json") {
			t.Fatal("ambiguous startup accepted")
		}
	}
}
