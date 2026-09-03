package vpndetection

import (
	"github.com/oapi-codegen/runtime/types"

	"github.com/vpndetection-io/sdk-go/internal/api"
)

// The wire shapes a lookup answers with, re-exported so a consumer never has to
// name an internal package.
type (
	LookupResponse = api.LookupResponse
	VpnDetail      = api.VpnDetail
	ClassDetail    = api.ClassDetail
	ProxyDetail    = api.ProxyDetail
	// Date is a calendar date with no time of day, as `last_seen` and
	// `first_seen` carry.
	Date = types.Date
)

// Result is what a lookup answers.
//
// A pointer member is one your plan does not include. It never means "we could
// not check", so nil and false are genuinely different answers: nil is "not in
// your plan", false is "checked, and no". The OrFalse readers below collapse
// the two for callers who only want to know whether an address is flagged.
//
// A detail object that is present but empty means the flag above it is false. A
// populated one always carries every one of its keys, empty values included.
type Result struct {
	// The answer as it was served, with the wire's own optionality intact. Its
	// fields are promoted, so r.IsVpn and r.Vpn read straight off the Result.
	LookupResponse

	// True when this answer was computed locally rather than served, which
	// happens for a bogon and only for a bogon.
	IsBogon bool `json:"is_bogon"`
}

// Go has no `??`, so each tier-gated flag gets a reader that treats "not in
// your plan" as false. Read the pointer field itself wherever absent and false
// must be told apart, which is the whole reason they are pointers.

func (r *Result) IsHostingOrFalse() bool  { return deref(r.IsHosting) }
func (r *Result) IsRelayOrFalse() bool    { return deref(r.IsRelay) }
func (r *Result) IsTorOrFalse() bool      { return deref(r.IsTor) }
func (r *Result) IsCdnOrFalse() bool      { return deref(r.IsCdn) }
func (r *Result) IsResproxyOrFalse() bool { return deref(r.IsResproxy) }
func (r *Result) IsDcproxyOrFalse() bool  { return deref(r.IsDcproxy) }
func (r *Result) IsMobproxyOrFalse() bool { return deref(r.IsMobproxy) }

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}
