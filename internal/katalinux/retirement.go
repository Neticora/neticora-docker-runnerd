package katalinux

// RetirementPolicy names the bounded customer-managed acquisition contract.
// It never promises detection of references held by arbitrary host administrators.
const RetirementPolicy = "broker-frozen-empty-v1"

type RetirementProof struct {
	Version     string `json:"version"`
	Policy      string `json:"policy"`
	RecordHash  string `json:"recordHash"`
	OperationID string `json:"operationId"`
}

// RetirementRecord is a permanent ownership tombstone, separate from the block
// allocation and native ACK. A quarantined record retains its last durable phase.
type RetirementRecord struct {
	Version     string             `json:"version"`
	Policy      string             `json:"policy"`
	Profile     string             `json:"profile"`
	Name        string             `json:"name"`
	Container   string             `json:"container"`
	SpecHash    string             `json:"specHash"`
	Generation  string             `json:"generation"`
	OperationID string             `json:"operationId"`
	Cgroup      CgroupRecord       `json:"cgroup"`
	Sandboxes   []SandboxDirectory `json:"sandboxes"`
	Processes   []Process          `json:"processes"`
	Phase       string             `json:"phase"`
	Quarantined bool               `json:"quarantined"`
	FencedAt    string             `json:"fencedAt,omitempty"`
	DisposedAt  string             `json:"disposedAt,omitempty"`
}
