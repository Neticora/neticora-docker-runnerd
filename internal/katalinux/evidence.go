package katalinux

type Process struct {
	PID        int    `json:"pid"`
	Start      string `json:"start"`
	Executable string `json:"executable"`
}
type Evidence struct {
	Sandboxes  []SandboxDirectory `json:"sandboxes,omitempty"`
	Cgroup     *CgroupRecord      `json:"cgroup,omitempty"`
	Block      *BlockRecord       `json:"block,omitempty"`
	Version    string             `json:"version"`
	Profile    string             `json:"profile"`
	Container  string             `json:"container"`
	SpecHash   string             `json:"specHash"`
	Generation string             `json:"generation"`
	ObservedAt string             `json:"observedAt"`
	Processes  []Process          `json:"processes"`
	Prepared   bool               `json:"prepared"`
	Absence    *PhysicalAbsence   `json:"absence"`
}

// Host-owned runtime directory identity captured while its original VM lives.
// A directory discovered only after a crash is never authority for deletion.
type SandboxDirectory struct {
	Root   string `json:"root"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

type PhysicalAbsence struct {
	CgroupRemoved     bool   `json:"cgroupRemoved,omitempty"`
	DeviceDetached    bool   `json:"deviceDetached,omitempty"`
	MountsRemoved     bool   `json:"mountsRemoved,omitempty"`
	ContainerAbsent   bool   `json:"containerAbsent"`
	SandboxAbsent     bool   `json:"sandboxAbsent"`
	VMAbsent          bool   `json:"vmAbsent"`
	NetworkRemoved    bool   `json:"networkRemoved"`
	StorageRemoved    bool   `json:"storageRemoved"`
	VerifiedAt        string `json:"verifiedAt"`
	ObservationSource string `json:"observationSource"`
}
