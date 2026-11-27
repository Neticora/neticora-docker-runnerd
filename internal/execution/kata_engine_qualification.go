//go:build runnerd_qualification

package execution

import "github.com/Neticora/neticora-docker-runnerd/internal/dockerengine"

// Only the known lab fault decorator can unwrap to a real bound Docker engine.
func kataRuntimeEngine(r Runtime) *dockerengine.Engine {
	if decorated, ok := r.(*labRuntime); ok {
		return kataRuntimeEngine(decorated.Runtime)
	}
	engine, _ := r.(*dockerengine.Engine)
	return engine
}
