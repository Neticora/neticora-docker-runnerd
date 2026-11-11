//go:build linux

package katalinux

import (
	"reflect"
	"strings"
	"testing"
)

func TestProcPrefixFieldsPreservesWhitespaceAndColumns(t *testing.T) {
	for _, line := range []string{"", " \t\n", "a", "a b c d e f extra columns", "a\u2003b\tc\nd\re\vf\fextra", " 1 2 8:1 /root /point rw - ext4 /dev/sda rw"} {
		for count := 1; count <= 6; count++ {
			out := make([]string, count)
			n := procPrefixFields(line, out)
			want := strings.Fields(line)
			if len(want) > count {
				want = want[:count]
			}
			if n != len(want) || !reflect.DeepEqual(out[:n], want) {
				// Fields may return nil for no columns; compare contents there.
				if n != 0 || len(want) != 0 {
					t.Fatalf("prefix changed fields: %q: %v != %v", line, out[:n], want)
				}
			}
		}
	}
}

func TestSandboxMountDecoderPreservesEscapes(t *testing.T) {
	for _, path := range []string{"/plain", `/space\040tab\011newline\012slash\134`, `/literal\134040`, `/unknown\377`, ""} {
		old := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, "\\").Replace(path)
		if got := decodeSandboxMountPath(path); got != old {
			t.Fatalf("changed decoding %q: %q != %q", path, got, old)
		}
	}
}
