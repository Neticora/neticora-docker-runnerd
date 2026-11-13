//go:build linux

package workerboundary

import _ "embed"

// NativeSource is the separately built, pinned namespace-init helper source.
// It is embedded for reproducible native qualification, not compiled at runtime
// by the installed broker. Packaging must ship a reviewed immutable executable.
//
//go:embed native/keeper.c
var NativeSource []byte
