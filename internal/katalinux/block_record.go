package katalinux

type BlockRecord struct {
	Version    string            `json:"version"`
	Profile    string            `json:"profile"`
	Name       string            `json:"name"`
	Labels     map[string]string `json:"labels"`
	Phase      string            `json:"phase"`
	UUID       string            `json:"uuid"`
	Bytes      uint64            `json:"bytes"`
	FileDevice uint64            `json:"fileDevice"`
	FileInode  uint64            `json:"fileInode"`
	LoopDevice uint64            `json:"loopDevice"`
	BootID     string            `json:"bootId"`
	UpdatedAt  string            `json:"updatedAt"`
}
