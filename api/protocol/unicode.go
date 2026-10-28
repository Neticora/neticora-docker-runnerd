package protocol

import (
	"fmt"
	"unicode/utf8"
)

// Check source bytes before encoding/json can replace malformed Unicode.
// Escaped backslashes are skipped: "\\ud800" is literal text, not a surrogate.
func validateJSONUnicode(data []byte) error {
	invalid := func() error { return fmt.Errorf("invalid host JSON Unicode") }
	if !utf8.Valid(data) {
		return invalid()
	}
	hex := func(offset int) (uint16, bool) {
		if offset+4 > len(data) {
			return 0, false
		}
		var value uint16
		for _, c := range data[offset : offset+4] {
			value <<= 4
			switch {
			case c >= '0' && c <= '9':
				value += uint16(c - '0')
			case c >= 'a' && c <= 'f':
				value += uint16(c - 'a' + 10)
			case c >= 'A' && c <= 'F':
				value += uint16(c - 'A' + 10)
			default:
				return 0, false
			}
		}
		return value, true
	}
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return invalid()
		}
		if data[i] != 'u' {
			continue
		}
		value, ok := hex(i + 1)
		if !ok {
			return invalid()
		}
		i += 4
		if value >= 0xdc00 && value <= 0xdfff {
			return invalid()
		}
		if value < 0xd800 || value > 0xdbff {
			continue
		}
		if i+2 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
			return invalid()
		}
		low, ok := hex(i + 3)
		if !ok || low < 0xdc00 || low > 0xdfff {
			return invalid()
		}
		i += 6
	}
	return nil
}
