//go:build !runnerd_qualification

package execution

import "github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"

func kataRuntimeEngine(r Runtime) *dockerengine.Engine {
	engine, _ := r.(*dockerengine.Engine)
	return engine
}
