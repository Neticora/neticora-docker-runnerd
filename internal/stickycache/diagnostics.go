package stickycache

import (
	"context"
	"errors"
	"os/exec"
	"regexp"
)

// Diagnostic contains only fixed outcome labels, numeric observations and
// validated native identities. LVM stderr and command output stay private.
type Diagnostic struct {
	Stage              string
	Result             string
	Command            string
	ExitStatus         int
	PoolBytes          uint64
	DataPercent        float64
	MetadataPercent    float64
	ReservationSlots   uint64
	VolumeBytes        uint64
	ReservationPercent float64
	MaxDataPercent     uint8
	MaxMetadataPercent uint8
	DataAllowed        bool
	MetadataAllowed    bool
	LVUUID             string
	FilesystemUUID     string
}

var lvmUUID = regexp.MustCompile(`^[A-Za-z0-9]{6}(?:-[A-Za-z0-9]{4}){5}-[A-Za-z0-9]{6}$`)

func DiagnosticUUID(uuid string) string {
	if lvmUUID.MatchString(uuid) {
		return uuid
	}
	return ""
}

func (l LVM) WithDiagnostics(record func(Diagnostic)) LVM {
	l.record = record
	return l
}

func (l LVM) diagnostic(event Diagnostic) {
	if l.record != nil {
		l.record(event)
	}
}

func commandDiagnostic(ctx context.Context, command string, err error) Diagnostic {
	event := Diagnostic{Stage: "lvm-command", Result: "ok", Command: command}
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.Is(ctx.Err(), context.DeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		event.Result = "timeout"
	case errors.Is(ctx.Err(), context.Canceled), errors.Is(err, context.Canceled):
		event.Result = "cancelled"
	case errors.As(err, &exit):
		event.Result, event.ExitStatus = "nonzero-exit", exit.ExitCode()
	default:
		event.Result = "command-unavailable"
	}
	return event
}
