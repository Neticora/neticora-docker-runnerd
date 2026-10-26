package conformance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"math/big"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func load(t *testing.T, n string) []byte {
	t.Helper()
	b, e := os.ReadFile("../" + n)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func decode(t *testing.T, b []byte) any {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if e := d.Decode(&v); e != nil {
		t.Fatal(e)
	}
	return v
}
func quote(s string) string {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	_ = e.Encode(s)
	return strings.ReplaceAll(strings.ReplaceAll(strings.TrimSuffix(b.String(), "\n"), `\u2028`, "\u2028"), `\u2029`, "\u2029")
}
func canonical(v any) (string, error) {
	switch x := v.(type) {
	case nil:
		return "null", nil
	case bool:
		return strconv.FormatBool(x), nil
	case string:
		return quote(x), nil
	case json.Number:
		q, ok := new(big.Rat).SetString(string(x))
		if !ok || !q.IsInt() || !q.Num().IsInt64() {
			return "", fmt.Errorf("unsafe integer")
		}
		n := q.Num().Int64()
		if n > 9007199254740991 || n < -9007199254740991 {
			return "", fmt.Errorf("unsafe integer")
		}
		return strconv.FormatInt(n, 10), nil
	case []any:
		a := make([]string, len(x))
		for i, v := range x {
			s, e := canonical(v)
			if e != nil {
				return "", e
			}
			a[i] = s
		}
		return "[" + strings.Join(a, ",") + "]", nil
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		a := make([]string, 0, len(keys))
		for _, k := range keys {
			s, e := canonical(x[k])
			if e != nil {
				return "", e
			}
			a = append(a, quote(k)+":"+s)
		}
		return "{" + strings.Join(a, ",") + "}", nil
	}
	return "", fmt.Errorf("non-JSON type")
}
func TestCanonicalHashes(t *testing.T) {
	for _, raw := range decode(t, load(t, "fixtures/canonicalization.json")).([]any) {
		v := raw.(map[string]any)
		t.Run(v["id"].(string), func(t *testing.T) {
			s, e := canonical(v["value"])
			if e != nil {
				t.Fatal(e)
			}
			sum := sha256.Sum256([]byte(s))
			if s != v["canonical"] || hex.EncodeToString(sum[:]) != v["sha256"] {
				t.Fatalf("canonical/hash mismatch: %s", s)
			}
		})
	}
}

type offlineLoader struct{}

func (offlineLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("network schema loading prohibited: %s", url)
}
func TestWireFixtures(t *testing.T) {
	doc, e := jsonschema.UnmarshalJSON(bytes.NewReader(load(t, "host-protocol.v1.yaml")))
	if e != nil {
		t.Fatal(e)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	c.UseLoader(offlineLoader{})
	if e = c.AddResource("urn:neticora:host-protocol", doc); e != nil {
		t.Fatal(e)
	}
	for _, raw := range decode(t, load(t, "fixtures/validation.json")).([]any) {
		v := raw.(map[string]any)
		t.Run(v["id"].(string), func(t *testing.T) {
			s, e := c.Compile("urn:neticora:host-protocol#/components/schemas/" + v["schema"].(string))
			if e != nil {
				t.Fatal(e)
			}
			valid := s.Validate(v["value"]) == nil
			if valid != v["valid"].(bool) {
				t.Fatalf("valid=%v want=%v", valid, v["valid"])
			}
		})
	}
}
func TestIdentityVectors(t *testing.T) {
	for _, raw := range decode(t, load(t, "fixtures/identities.json")).([]any) {
		v := raw.(map[string]any)
		p := v["previous"].(map[string]any)
		i := v["incoming"].(map[string]any)
		got := "new"
		if p["id"] == i["id"] {
			got = "conflict"
			if p["hash"] == i["hash"] && p["sequence"] == i["sequence"] {
				got = "replay"
			}
		} else if i["sequence"] != nil && i["sequence"] == p["sequence"] {
			got = "conflict"
		}
		if got != v["expected"] {
			t.Fatalf("%s: got %s", v["id"], got)
		}
	}
}
func TestManifest(t *testing.T) {
	m := decode(t, load(t, "fixtures/manifest.json")).(map[string]any)
	files := m["files"].([]any)
	var last string
	for _, raw := range files {
		f := raw.(map[string]any)
		p := f["path"].(string)
		if p <= last || strings.ContainsAny(p, "/\\") || p == "manifest.json" {
			t.Fatal("unsafe/unsorted manifest")
		}
		last = p
		sum := sha256.Sum256(load(t, "fixtures/"+p))
		if hex.EncodeToString(sum[:]) != f["sha256"] {
			t.Fatal("fixture checksum mismatch: " + p)
		}
	}
	schema := sha256.Sum256(load(t, "host-protocol.v1.yaml"))
	corpus, e := canonical(files)
	if e != nil {
		t.Fatal(e)
	}
	ch := sha256.Sum256([]byte(corpus))
	mh := sha256.Sum256(load(t, "fixtures/manifest.json"))
	t.Logf("protocol=%s schemaSha256=%x fixtureManifestSha256=%x fixtureCorpusSha256=%x", m["protocolVersion"], schema, mh, ch)
}
