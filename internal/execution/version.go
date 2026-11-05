package execution

import "runtime/debug"

// Version identifies the actual executable, never a configuration claim.
func Version() string {
	i, ok := debug.ReadBuildInfo()
	if !ok {
		return "development"
	}
	if i.Main.Version != "" && i.Main.Version != "(devel)" {
		return i.Main.Version
	}
	revision := "development"
	dirty := false
	for _, s := range i.Settings {
		if s.Key == "vcs.revision" {
			revision = s.Value
		}
		if s.Key == "vcs.modified" && s.Value == "true" {
			dirty = true
		}
	}
	if dirty {
		revision += "-dirty"
	}
	return revision
}
