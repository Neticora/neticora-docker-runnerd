//go:build !linux

package control

import (
	"context"
	"errors"
)

type Snapshot struct {
	QualificationState            string   `json:"qualificationState"`
	PlatformAdmissionEnabled      bool     `json:"platformAdmissionEnabled"`
	DispatchBlockers              []string `json:"dispatchBlockers"`
	InventoryState                string   `json:"inventoryState,omitempty"`
	InventoryGeneration           string   `json:"inventoryGeneration,omitempty"`
	InventoryObservedAt           string   `json:"inventoryObservedAt,omitempty"`
	InventoryFresh                bool     `json:"inventoryFresh"`
	ConnectionRecoveryOperationID string   `json:"connectionRecoveryOperationId,omitempty"`
	ConnectionRecoveryReason      string   `json:"connectionRecoveryReason,omitempty"`
	ObservationSessionEpoch       string   `json:"observationSessionEpoch,omitempty"`
	ObservationBootID             string   `json:"observationBootId,omitempty"`
	ObservationEndpointIdentity   string   `json:"observationEndpointIdentity,omitempty"`
	Platform                      string   `json:"platform,omitempty"`
	LastHeartbeat                 string   `json:"lastHeartbeat,omitempty"`
	ExecutionReason               string   `json:"executionReason,omitempty"`
	ExecutionEnabled              bool     `json:"executionEnabled,omitempty"`
	State                         string   `json:"state"`
	AdmissionEnabled              bool     `json:"admissionEnabled"`
	RuntimeQualified              bool     `json:"runtimeQualified"`
	RecoveryReady                 bool     `json:"recoveryReady"`
	RecoveryReason                string   `json:"recoveryReason"`
}
type Server struct{}

func (*Server) SetDurableDrain(func() error) {}

func (*Server) ExposeExecutions(func(context.Context, string, string) (any, error)) {}

func Listen(string, func() Snapshot, func(), func(string)) (*Server, error) {
	return nil, errors.New("local control supports Linux only")
}
func (*Server) Serve() error                   { return errors.New("unsupported platform") }
func (*Server) Shutdown(context.Context) error { return nil }

func (*Server) Close() error { return nil }
