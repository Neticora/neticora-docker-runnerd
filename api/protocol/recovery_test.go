package protocol

import "testing"

func TestRecoveryLookupsAreBoundedGenerationKeysNotAuthority(t *testing.T) {
	for _, raw := range []string{`{"entries":[]}`, `{"entries":[{"executionId":"same","generation":"1"},{"executionId":"same","generation":"2"}]}`} {
		if _, err := DecodeRecoveryRequest([]byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
	for _, raw := range []string{`{"entries":[{"executionId":"same","generation":"1"},{"executionId":"same","generation":"1"}]}`, `{"entries":[{"executionId":"same","generation":"0"}]}`, `{"entries":[],"admissionEnabled":true}`} {
		if _, err := DecodeRecoveryRequest([]byte(raw)); err == nil {
			t.Fatal("invalid recovery lookup accepted")
		}
	}
}
