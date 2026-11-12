//go:build linux

package broker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"github.com/Neticora/neticora-docker-runnerd/internal/hostfs"
)

// NetworkGuard pins an operator-reviewed runtime network without granting the
// controller authority to create networks or alter the customer's firewall.
// Both this descriptor and the nft binary must be in the signed Kata file map.
type NetworkGuard struct {
	Version      string `json:"version"`
	NetworkID    string `json:"networkId"`
	Bridge       string `json:"bridge"`
	IPv6         bool   `json:"ipv6"`
	NFTBinary    string `json:"nftBinary"`
	Table        string `json:"table"`
	InetSHA256   string `json:"inetSha256"`
	BridgeSHA256 string `json:"bridgeSha256"`
}

var networkGuardName = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,31}$`)
var networkGuardBridge = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,14}$`)

func readNetworkGuard(file, network string, files map[string]string) (NetworkGuard, error) {
	var g NetworkGuard
	raw, err := hostfs.ReadPrivate(file, 16384)
	if err != nil || !digest(files[file]) || hashNetworkBytes(raw) != files[file] || decode(raw, &g) != nil {
		return g, ErrRejected
	}
	if g.Version != "runnerd-network-guard-v1" || !digest(network) || g.NetworkID != network || !networkGuardBridge.MatchString(g.Bridge) || !networkGuardName.MatchString(g.Table) || !digest(g.InetSHA256) || !digest(g.BridgeSHA256) || !digest(files[g.NFTBinary]) || !filepath.IsAbs(g.NFTBinary) || filepath.Clean(g.NFTBinary) != g.NFTBinary {
		return g, ErrRejected
	}
	return g, nil
}

func hashNetworkBytes(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

// nft includes volatile object handles and version metadata in readback. Strip
// only these fields; rule ordering, priorities, expressions and policies remain
// covered. Counters and other mutable rule expressions are deliberately rejected.
func networkTableHash(raw []byte, family, table string) (string, error) {
	canonical, err := protocol.CanonicalizeJSON(raw)
	if err != nil {
		return "", ErrRejected
	}
	var root struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if decode(canonical, &root) != nil || len(root.NFTables) < 3 || len(root.NFTables) > 256 {
		return "", ErrRejected
	}
	objects := make([]map[string]any, 0, len(root.NFTables))
	tables, chains, rules := 0, 0, 0
	for _, object := range root.NFTables {
		if len(object) != 1 {
			return "", ErrRejected
		}
		for kind, rawObject := range object {
			if kind == "metainfo" {
				continue
			}
			var item map[string]any
			if json.Unmarshal(rawObject, &item) != nil || item["family"] != family {
				return "", ErrRejected
			}
			switch kind {
			case "table":
				if item["name"] != table {
					return "", ErrRejected
				}
				tables++
			case "chain", "rule":
				if item["table"] != table {
					return "", ErrRejected
				}
				if kind == "chain" {
					chains++
				} else {
					rules++
				}
			default:
				return "", ErrRejected
			}
			delete(item, "handle")
			objects = append(objects, map[string]any{kind: item})
		}
	}
	if tables != 1 || chains == 0 || rules == 0 {
		return "", ErrRejected
	}
	data, err := json.Marshal(objects)
	if err != nil || bytes.Contains(data, []byte(`"counter"`)) {
		return "", ErrRejected
	}
	canonical, err = protocol.CanonicalizeJSON(data)
	if err != nil {
		return "", ErrRejected
	}
	return hashNetworkBytes(canonical), nil
}

type boundedNetworkOutput struct{ data bytes.Buffer }

func (b *boundedNetworkOutput) Write(p []byte) (int, error) {
	if b.data.Len()+len(p) > 256<<10 {
		return 0, ErrRejected
	}
	return b.data.Write(p)
}

func (g NetworkGuard) check(ctx context.Context, file, network string, files map[string]string, inspect func(context.Context, string, string, bool) error) error {
	current, err := readNetworkGuard(file, network, files)
	if err != nil || current != g || hostfs.CheckAncestors(filepath.Dir(g.NFTBinary)) != nil {
		return ErrRejected
	}
	info, err := os.Lstat(g.NFTBinary)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return ErrRejected
	}
	f, err := os.Open(g.NFTBinary)
	if err != nil {
		return ErrRejected
	}
	h := sha256.New()
	n, readErr := io.Copy(h, io.LimitReader(f, 32<<20+1))
	closeErr := f.Close()
	if readErr != nil || closeErr != nil || n > 32<<20 || hex.EncodeToString(h.Sum(nil)) != files[g.NFTBinary] {
		return ErrRejected
	}
	if err = inspect(ctx, network, g.Bridge, g.IPv6); err != nil {
		return err
	}
	for _, family := range []string{"inet", "bridge"} {
		timeout, cancel := context.WithTimeout(ctx, 2*time.Second)
		cmd := exec.CommandContext(timeout, g.NFTBinary, "--json", "list", "table", family, g.Table)
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
		var out boundedNetworkOutput
		cmd.Stdout = &out
		err = cmd.Run()
		cancel()
		expected := g.InetSHA256
		if family == "bridge" {
			expected = g.BridgeSHA256
		}
		actual, hashErr := networkTableHash(out.data.Bytes(), family, g.Table)
		if err != nil || hashErr != nil || actual != expected {
			return ErrRejected
		}
	}
	return ctx.Err()
}
