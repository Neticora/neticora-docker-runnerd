//go:build linux

package onboarding

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

func TestReadMaskedToken(t *testing.T) {
	for _, tc := range []struct {
		name, input, want, display string
	}{
		{"typing", "original-secret-token\r", "original-secret-token", strings.Repeat("*", 21)},
		{"paste", "\x1b[200~original-secret-token\x1b[201~\r", "original-secret-token", strings.Repeat("*", 21)},
		{"unframed-paste", "original-secret-token\n", "original-secret-token", strings.Repeat("*", 21)},
		{"backspace", "abc\x7f\bde\r", "ade", "***\b \b\b \b**"},
		{"clear-line", "abc\x15replacement\r", "replacement", "***" + strings.Repeat("\b \b", 3) + strings.Repeat("*", 11)},
		{"leading-backspace", "\b\x7ftoken\r", "token", "*****"},
		{"exact-bytes", " token-_ABC09= \r", " token-_ABC09= ", strings.Repeat("*", 15)},
		{"limit", strings.Repeat("a", maxTokenInput) + "\r", strings.Repeat("a", maxTokenInput), strings.Repeat("*", maxTokenInput)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			value, err := readMaskedToken(strings.NewReader(tc.input), &output)
			defer clear(value)
			if err != nil || string(value) != tc.want || output.String() != tc.display {
				t.Fatal("token bytes or masked display differ from expected result")
			}
		})
	}
}

func TestReadMaskedTokenRejectsInvalidInput(t *testing.T) {
	for name, input := range map[string]string{
		"cancel": "secret\x03", "eof-key": "secret\x04", "eof": "secret",
		"multiline-paste":       "\x1b[200~secret\nsecond-line\x1b[201~\r",
		"carriage-return-paste": "\x1b[200~secret\r\n\x1b[201~\r",
		"control-paste":         "\x1b[200~secret\x7f\x1b[201~\r",
		"nested-paste":          "\x1b[200~secret\x1b[200~other\x1b[201~\r",
		"unclosed-paste":        "\x1b[200~secret\r",
		"unexpected-paste-end":  "secret\x1b[201~\r",
		"truncated-paste":       "\x1b[20", "cursor-key": "secret\x1b[A",
		"oversize":       strings.Repeat("a", maxTokenInput+1) + "\r",
		"oversize-paste": "\x1b[200~" + strings.Repeat("a", maxTokenInput+1) + "\x1b[201~\r",
	} {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			value, err := readMaskedToken(strings.NewReader(input), &output)
			if err == nil || value != nil {
				t.Fatal("invalid token was accepted")
			}
			if strings.Trim(output.String(), "*") != "" || len(output.String()) > maxTokenInput {
				t.Fatal("output exposed input or exceeded the display bound")
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatal("error exposed token contents")
			}
		})
	}
}

type failedTokenOutput struct{ short bool }

func (w failedTokenOutput) Write([]byte) (int, error) {
	if w.short {
		return 0, nil
	}
	return 0, errors.New("output unavailable")
}

func TestReadMaskedTokenOutputFailure(t *testing.T) {
	for _, short := range []bool{false, true} {
		value, err := readMaskedToken(strings.NewReader("secret\r"), failedTokenOutput{short: short})
		if err == nil || value != nil {
			t.Fatal("output failure did not discard token")
		}
	}
}

func tokenPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = master.Close() })
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	number, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = slave.Close() })
	return master, slave
}

func readTokenPTY(t *testing.T, master *os.File, suffix string) string {
	t.Helper()
	var output strings.Builder
	deadline := time.Now().Add(5 * time.Second)
	for !strings.HasSuffix(output.String(), suffix) {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatal("timed out waiting for masked terminal output")
		}
		poll := []unix.PollFd{{Fd: int32(master.Fd()), Events: unix.POLLIN}}
		if _, err := unix.Poll(poll, int(remaining.Milliseconds())+1); err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			t.Fatal(err)
		}
		if poll[0].Revents&unix.POLLIN == 0 {
			continue
		}
		var buffer [256]byte
		n, err := master.Read(buffer[:])
		if err != nil {
			t.Fatal(err)
		}
		output.Write(buffer[:n])
	}
	return output.String()
}

func TestPromptTokenTerminal(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		cancel      bool
	}{
		{"typed", "original-secret-token\r", false},
		{"pasted", "\x1b[200~original-secret-token\x1b[201~\r", false},
		{"cancelled", "original-secret-token\x03queued-secret\r", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			master, slave := tokenPTY(t)
			before, err := term.GetState(int(slave.Fd()))
			if err != nil {
				t.Fatal(err)
			}
			type result struct {
				value []byte
				err   error
			}
			done := make(chan result, 1)
			go func() {
				value, err := promptToken(slave, slave)
				done <- result{value, err}
			}()
			if got := readTokenPTY(t, master, "Enrollment token: "); got != "\x1b[?2004hEnrollment token: " {
				t.Fatal("unexpected enrollment prompt")
			}
			mode, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
			if err != nil || mode.Lflag&unix.ECHO != 0 {
				t.Fatal("terminal echo is enabled while accepting the token")
			}
			if _, err := io.WriteString(master, tc.input); err != nil {
				t.Fatal(err)
			}
			if got := readTokenPTY(t, master, "\r\n"); got != strings.Repeat("*", 21)+"\x1b[?2004l\r\n" {
				t.Fatal("terminal did not display only masked token bytes")
			}
			select {
			case got := <-done:
				defer clear(got.value)
				if tc.cancel {
					if got.err == nil || got.value != nil {
						t.Fatal("cancelled token was returned")
					}
				} else if got.err != nil || string(got.value) != "original-secret-token" {
					t.Fatal("terminal changed token bytes")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("token prompt did not return")
			}
			after, err := term.GetState(int(slave.Fd()))
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("terminal settings were not restored")
			}
			queued, err := unix.IoctlGetInt(int(slave.Fd()), unix.TIOCINQ)
			if err != nil || queued != 0 {
				t.Fatal("pasted bytes remain queued after the token prompt")
			}
		})
	}
}

func TestPromptTokenRestoresTerminalOnOutputFailure(t *testing.T) {
	_, slave := tokenPTY(t)
	before, err := term.GetState(int(slave.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	value, err := promptToken(slave, failedTokenOutput{})
	if err == nil || value != nil {
		t.Fatal("output failure was accepted")
	}
	after, err := term.GetState(int(slave.Fd()))
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("terminal settings were not restored after output failure")
	}
}
