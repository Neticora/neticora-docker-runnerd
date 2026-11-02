package identity

import (
	"encoding/json"
	"github.com/Neticora/neticora-docker-runnerd/api/protocol"
	"strconv"
)

// NarrowPolicy intersects authenticated server configuration with root-owned local
// ceilings. It does not activate admission or overwrite local customer policy.
func NarrowPolicy(local, remote protocol.LocalPolicy) (protocol.LocalPolicy, error) {
	for _, policy := range []protocol.LocalPolicy{local, remote} {
		raw, err := json.Marshal(policy)
		if err != nil {
			return protocol.LocalPolicy{}, err
		}
		if err = protocol.ValidateInboundJSON("LocalPolicy", raw); err != nil {
			return protocol.LocalPolicy{}, err
		}
	}
	minimum := func(a, b protocol.UInt64String) protocol.UInt64String {
		x, _ := strconv.ParseUint(string(a), 10, 64)
		y, _ := strconv.ParseUint(string(b), 10, 64)
		if x < y {
			return a
		}
		return b
	}
	result := protocol.LocalPolicy{Generation: remote.Generation, AllowedProfiles: []string{}, AllowedTrustClasses: []protocol.LocalPolicyAllowedTrustClasses{}, Limits: protocol.ResourceBudget{CpuMillis: minimum(local.Limits.CpuMillis, remote.Limits.CpuMillis), MemoryBytes: minimum(local.Limits.MemoryBytes, remote.Limits.MemoryBytes), StorageBytes: minimum(local.Limits.StorageBytes, remote.Limits.StorageBytes), Slots: minimum(local.Limits.Slots, remote.Limits.Slots)}}
	for _, profile := range local.AllowedProfiles {
		for _, allowed := range remote.AllowedProfiles {
			if profile == allowed {
				result.AllowedProfiles = append(result.AllowedProfiles, profile)
				break
			}
		}
	}
	for _, trust := range local.AllowedTrustClasses {
		for _, allowed := range remote.AllowedTrustClasses {
			if trust == allowed {
				result.AllowedTrustClasses = append(result.AllowedTrustClasses, trust)
				break
			}
		}
	}
	return result, nil
}
