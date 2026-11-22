//go:build linux

package onboarding

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

const maxTokenInput = 16384

// promptToken disables terminal echo before displaying the prompt. Raw mode
// lets us echo only stars and handle editing without exposing token bytes.
func promptToken(input *os.File, output io.Writer) (value []byte, err error) {
	fd := int(input.Fd())
	previous, err := term.MakeRaw(fd)
	if err != nil {
		return nil, errors.New("cannot protect enrollment token input")
	}
	defer func() {
		// Discard queued input before restoring echo, including any remaining
		// pasted bytes after cancellation or an input/output error.
		flushErr := unix.IoctlSetInt(fd, unix.TCFLSH, unix.TCIFLUSH)
		outputErr := tokenOutput(output, "\x1b[?2004l\r\n")
		restoreErr := term.Restore(fd, previous)
		if flushErr != nil || outputErr != nil || restoreErr != nil {
			clear(value)
			value = nil
			err = errors.New("cannot restore enrollment token terminal")
		}
	}()
	if err = tokenOutput(output, "\x1b[?2004hEnrollment token: "); err != nil {
		return nil, err
	}
	return readMaskedToken(input, output)
}

func tokenOutput(output io.Writer, text string) error {
	n, err := io.WriteString(output, text)
	if err != nil || n != len(text) {
		return errors.New("cannot display enrollment token prompt")
	}
	return nil
}

// readMaskedToken preserves the original token bytes. Bracketed-paste wrappers
// are terminal framing, not part of the token. Multiline/control-character
// pastes are rejected rather than silently changing the enrollment identity.
func readMaskedToken(input io.Reader, output io.Writer) ([]byte, error) {
	value := make([]byte, 0, maxTokenInput)
	accepted := false
	defer func() {
		if !accepted {
			clear(value[:cap(value)])
		}
	}()
	pasting, invalid := false, false
	var b [1]byte
	for {
		if _, err := io.ReadFull(input, b[:]); err != nil {
			return nil, errors.New("enrollment token input ended")
		}
		c := b[0]
		if c == '\x1b' {
			var sequence [5]byte
			for i := range sequence {
				if _, err := io.ReadFull(input, sequence[i:i+1]); err != nil {
					return nil, errors.New("incomplete enrollment token paste")
				}
				prefix := string(sequence[:i+1])
				if prefix != "[200~"[:i+1] && prefix != "[201~"[:i+1] {
					return nil, errors.New("unsupported enrollment token input")
				}
			}
			switch string(sequence[:]) {
			case "[200~":
				if pasting {
					invalid = true
				}
				pasting = true
			case "[201~":
				if !pasting {
					invalid = true
				}
				pasting = false
			default:
				return nil, errors.New("unsupported enrollment token input")
			}
			continue
		}
		if !pasting {
			switch c {
			case '\r', '\n':
				if invalid {
					return nil, errors.New("enrollment token paste must be a single line within the input limit")
				}
				accepted = true
				return value, nil
			case '\x03', '\x04':
				return nil, errors.New("enrollment token input cancelled")
			case '\b', '\x7f':
				if len(value) > 0 {
					value[len(value)-1] = 0
					value = value[:len(value)-1]
					if err := tokenOutput(output, "\b \b"); err != nil {
						return nil, err
					}
				}
				continue
			case '\x15': // Ctrl+U clears the current entry.
				for len(value) > 0 {
					value[len(value)-1] = 0
					value = value[:len(value)-1]
					if err := tokenOutput(output, "\b \b"); err != nil {
						return nil, err
					}
				}
				continue
			}
		}
		if c < ' ' || c == '\x7f' || len(value) == maxTokenInput {
			invalid = true
			continue
		}
		if invalid {
			continue
		}
		value = append(value, c)
		if err := tokenOutput(output, "*"); err != nil {
			return nil, err
		}
	}
}
