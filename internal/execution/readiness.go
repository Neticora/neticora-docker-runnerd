package execution

import "time"

type Readiness struct {
	RuntimeQualified         bool     `json:"runtimeQualified"`
	QualificationState       string   `json:"qualificationState"`
	PlatformAdmissionEnabled bool     `json:"platformAdmissionEnabled"`
	DispatchBlockers         []string `json:"dispatchBlockers"`
}

// Readiness separates acceptance, remote admission, local drain and recovery.
// This projection grants no execution authority.
func (c *Controller) Readiness(now time.Time) Readiness {
	out := Readiness{QualificationState: "unverified", DispatchBlockers: []string{}}
	r, ok := c.Remote.(*HostRemote)
	if ok && r.CheckQualification != nil && r.CheckQualification() == nil {
		out.RuntimeQualified = true
		out.QualificationState = "verified"
	} else {
		out.DispatchBlockers = append(out.DispatchBlockers, "current-signed-qualification-required")
	}
	if ok {
		enabled, fresh := r.AdmissionObservation(now)
		out.PlatformAdmissionEnabled = enabled && fresh
		if !fresh {
			out.DispatchBlockers = append(out.DispatchBlockers, "platform-admission-observation-stale")
		} else if !enabled {
			out.DispatchBlockers = append(out.DispatchBlockers, "platform-admission-disabled")
		}
	} else {
		out.DispatchBlockers = append(out.DispatchBlockers, "platform-admission-unavailable")
	}
	if c.Drained == nil || c.Drained() {
		out.DispatchBlockers = append(out.DispatchBlockers, "local-drain-enabled")
	}
	if c.Status() != "ready" {
		out.DispatchBlockers = append(out.DispatchBlockers, c.Status())
	}
	return out
}
