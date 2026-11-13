package vpndetection

import (
	"runtime/debug"
	"strings"
	"sync"
)

// modulePath is this module as a program built on it records it in its build
// information.
const modulePath = "github.com/vpndetection-io/sdk-go/v5"

// userAgent names this SDK and its version on every request, object storage's
// included: vpndetection-go/5.14.0. The version is the one the program was
// built with, read once from its build information, since a Go module carries
// no version of its own beyond its tag. A wrapping program puts its own name
// first in the transport it passes to WithHTTPClient, which sees this header
// already set.
var userAgent = sync.OnceValue(func() string {
	info, ok := debug.ReadBuildInfo()
	return agentFrom(info, ok)
})

// agentFrom reads this module's version from a program's build information.
// Its own tests, a local replace and a build without module information all
// read as devel: "(devel)" is what Go records there, and parentheses are no
// part of a product version.
func agentFrom(info *debug.BuildInfo, ok bool) string {
	if !ok || info == nil {
		return "vpndetection-go/devel"
	}
	module := &info.Main
	for _, dep := range info.Deps {
		if dep.Path == modulePath {
			module = dep
			break
		}
	}
	if module.Path != modulePath {
		return "vpndetection-go/devel"
	}
	if module.Replace != nil {
		module = module.Replace
	}
	return "vpndetection-go/" + productVersion(module.Version)
}

// productVersion drops a tag's leading v, and reads anything that is not a
// version as devel: "(devel)", or the empty one of a local path's replace.
func productVersion(version string) string {
	version = strings.TrimPrefix(version, "v")
	if version == "" || strings.ContainsAny(version, "() \t/") {
		return "devel"
	}
	return version
}
