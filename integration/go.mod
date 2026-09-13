// A module of its own, requiring a RELEASED version of the SDK: the point of
// this suite is the artifact a stranger gets from the proxy, so a replace
// directive pointing at the parent directory would quietly defeat all of it.
//
// scripts/run.sh moves the requirement to the newest published tag for the run
// and puts this file back afterwards.
module github.com/vpndetection-io/sdk-go/v3/integration

go 1.24.0

require github.com/vpndetection-io/sdk-go/v3 v3.1.0

require (
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/oapi-codegen/runtime v1.7.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
)
