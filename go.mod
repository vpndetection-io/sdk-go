// The path carries the MAJOR version, and it is not optional.
//
// From v2 onwards Go REQUIRES the module path to end in /vN, and a tag without
// it is not a release - it is invisible. `go get` silently resolves the newest
// v1 instead, so the break shows up as a customer on an old version rather than
// as an error anyone sees. v2.0.0 and v3.0.0 were both tagged this way and
// neither was ever downloadable. Bumping the major means editing this line,
// every internal import, integration/go.mod and the README, in the same commit
// as the tag.
module github.com/vpndetection-io/sdk-go/v3

go 1.24.0

require (
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/oapi-codegen/runtime v1.7.0
	golang.org/x/sync v0.19.0
)

require (
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
)
