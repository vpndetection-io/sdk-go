// Package held lets the middleware package read what package vpndetection keeps
// unexported: which members of a lookup answer the wire left out although their
// Go type is not optional.
package held

// Unserved answers the wire paths (asn.type) of the members result, a
// *vpndetection.Result, did not carry although its Go type cannot say so, and
// nil for anything else. Package vpndetection sets it when it loads.
var Unserved = func(result any) []string { return nil }
