// Package version reports the build version of the binary.
package version

import "runtime/debug"

// tag is set on release builds with
// -ldflags "-X github.com/Dani4x2y/driftrecon/internal/version.tag=v1.2.3".
var tag string

// String returns the release tag, falling back to the module version recorded
// by the Go toolchain and finally to "dev".
func String() string {
	if tag != "" {
		return tag
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	return "dev"
}
