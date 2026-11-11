//go:build linux

package katalinux

import "strings"

// Parse only the required leading columns, preserving strings.Fields whitespace
// semantics without allocating a slice for every maps/mountinfo/stat line. The
// caller still supplies a fresh observation; no process/reference state is kept.
func procPrefixFields(line string, fields []string) int {
	n := 0
	for field := range strings.FieldsSeq(line) {
		if n == len(fields) {
			break
		}
		fields[n] = field
		n++
		if n == len(fields) {
			break
		}
	}
	return n
}

// Replacer is concurrency-safe. This is an immutable decoding rule, not a
// cached mount observation, namespace identity or authorization decision.
var sandboxMountEscapes = strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, "\\")
