package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"syscall"
)

type requestFailure struct {
	message string
	kind    string
	status  int
}

func (failure *requestFailure) Error() string { return failure.message }

// RequestFailureDetails exposes only a fixed classification and optional HTTP
// status. Error strings can contain request URLs or remote response data.
func RequestFailureDetails(err error) (kind string, status int) {
	var failure *requestFailure
	if errors.As(err, &failure) {
		return failure.kind, failure.status
	}
	return "request-unavailable", 0
}

func transportFailureKind(err error) string {
	var certificate *tls.CertificateVerificationError
	var authority x509.UnknownAuthorityError
	var dns *net.DNSError
	var socket net.Error
	switch {
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.As(err, &certificate), errors.As(err, &authority):
		return "tls-verification"
	case errors.As(err, &dns):
		return "dns"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection-refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection-reset"
	case errors.As(err, &socket) && socket.Timeout():
		return "timeout"
	default:
		return "network"
	}
}
