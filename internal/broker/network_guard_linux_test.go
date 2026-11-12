//go:build linux

package broker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const networkTableFixture = `{"nftables":[{"metainfo":{"version":"1","json_schema_version":1}},{"table":{"family":"inet","name":"nr9_f4","handle":1}},{"chain":{"family":"inet","table":"nr9_f4","name":"input","handle":2,"type":"filter","hook":"input","prio":-20,"policy":"accept"}},{"rule":{"family":"inet","table":"nr9_f4","chain":"input","handle":3,"expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"nr9-f4"}},{"drop":null}]}}]}`

func TestNetworkGuardHashPreservesIsolationSemantics(t *testing.T) {
	base, err := networkTableHash([]byte(networkTableFixture), "inet", "nr9_f4")
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range [][2]string{{`"handle":1`, `"handle":11`}, {`"version":"1"`, `"version":"2"`}} {
		actual, err := networkTableHash([]byte(strings.Replace(networkTableFixture, change[0], change[1], 1)), "inet", "nr9_f4")
		if err != nil || actual != base {
			t.Fatal("volatile metadata changed policy identity", err)
		}
	}
	for _, change := range [][2]string{{`"drop":null`, `"accept":null`}, {`"prio":-20`, `"prio":20`}, {`"nr9-f4"`, `"another-bridge"`}, {`"policy":"accept"`, `"policy":"drop"`}} {
		actual, err := networkTableHash([]byte(strings.Replace(networkTableFixture, change[0], change[1], 1)), "inet", "nr9_f4")
		if err == nil && actual == base {
			t.Fatal("changed firewall semantics retained policy identity")
		}
	}
	for _, invalid := range []string{strings.ReplaceAll(networkTableFixture, `"inet"`, `"bridge"`), strings.ReplaceAll(networkTableFixture, `"nr9_f4"`, `"other"`), strings.Replace(networkTableFixture, `{"drop":null}`, `{"counter":{"packets":0,"bytes":0}}`, 1), `{"nftables":[],"nftables":[]}`, `{"nftables":[]}`} {
		if _, err := networkTableHash([]byte(invalid), "inet", "nr9_f4"); err == nil {
			t.Fatal("ambiguous or wrong table accepted")
		}
	}
}

func TestNetworkGuardRequiresSignedExactNetworkAndDescriptor(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "network.json")
	network := strings.Repeat("a", 64)
	g := NetworkGuard{Version: "runnerd-network-guard-v1", NetworkID: network, Bridge: "nr9-f4", NFTBinary: "/usr/sbin/nft", Table: "nr9_f4", InetSHA256: strings.Repeat("b", 64), BridgeSHA256: strings.Repeat("c", 64)}
	raw, _ := json.Marshal(g)
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{file: hashNetworkBytes(raw), g.NFTBinary: strings.Repeat("d", 64)}
	if got, err := readNetworkGuard(file, network, files); err != nil || got != g {
		t.Fatal("signed descriptor rejected", err)
	}
	if _, err := readNetworkGuard(file, strings.Repeat("e", 64), files); err == nil {
		t.Fatal("network substitution accepted")
	}
	delete(files, g.NFTBinary)
	if _, err := readNetworkGuard(file, network, files); err == nil {
		t.Fatal("unsigned privileged binary accepted")
	}
	files[g.NFTBinary] = strings.Repeat("d", 64)
	if err := os.WriteFile(file, append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readNetworkGuard(file, network, files); err == nil {
		t.Fatal("descriptor replacement accepted")
	}
}

func TestNetworkGuardOutputIsBounded(t *testing.T) {
	var b boundedNetworkOutput
	if n, err := b.Write(make([]byte, 256<<10)); n != 256<<10 || err != nil {
		t.Fatal(n, err)
	}
	if _, err := b.Write([]byte{0}); err == nil {
		t.Fatal("unbounded privileged output")
	}
}
