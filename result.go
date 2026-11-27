package vpndetection

import (
	"github.com/oapi-codegen/runtime/types"

	"github.com/vpndetection-io/sdk-go/v5/internal/api"
	"github.com/vpndetection-io/sdk-go/v5/internal/held"
)

// The wire shapes a lookup answers with, re-exported so a consumer never has to
// name an internal package.
type (
	LookupResponse    = api.LookupResponse
	VpnDetail         = api.VpnDetail
	ClassDetail       = api.ClassDetail
	ProxyDetail       = api.ProxyDetail
	PubproxyDetail    = api.PubproxyDetail
	CarrierDetail     = api.CarrierDetail
	SatelliteDetail   = api.SatelliteDetail
	SSHDetail         = api.SSHDetail
	SMTPDetail        = api.SMTPDetail
	WebDetail         = api.WebDetail
	DNSResolverDetail = api.DNSResolverDetail
	BitTorrentDetail  = api.BitTorrentDetail
	// BotDetail is whose bot uses the address, on a paid plan: its operator,
	// its bots as their user agents name them, what they do, and whether the
	// operator vouches for the address. Empty when IsBot is false.
	BotDetail = api.BotDetail
	// Location is where the address is, on every answer, with or without a
	// key. The finer members, Region down to AccuracyRadius, are a paid plan's.
	Location = api.Location
	// Asn is the AS announcing the address, on every answer, with or without a
	// key: Asn is 0 where none does. Its Type, the kind of network, is a paid
	// plan's, and reads empty on Unlimited.
	Asn = api.Asn
	// Company is who uses the address, on a paid plan.
	Company = api.Company
	// AbuseContact is where to report abuse from the address, on a paid plan.
	AbuseContact = api.AbuseContact
	// Date is a calendar date with no time of day, as `last_seen` and
	// `first_seen` carry.
	Date = types.Date
	// UserAgentVerdict is whose bot the user agent sent with a lookup names,
	// and whether this address bears that out. Only an answer to a lookup
	// sent with UserAgent carries one, with every field.
	UserAgentVerdict = api.UserAgentVerdict
	// Verdict is UserAgentVerdict.Verdict: VerdictVerified, VerdictSpoofed,
	// VerdictUnverifiable or VerdictNotBot.
	Verdict = api.UserAgentVerdictVerdict
)

// The verdicts a UserAgentVerdict carries.
const (
	// VerdictVerified is an agent whose operator vouches for this address as it.
	VerdictVerified = api.Verified
	// VerdictSpoofed is a bot whose operator does not vouch for this address,
	// or an address that posed as the bot before.
	VerdictSpoofed = api.Spoofed
	// VerdictUnverifiable is a bot no published list or registered space can
	// confirm.
	VerdictUnverifiable = api.Unverifiable
	// VerdictNotBot is a browser, an app or a script.
	VerdictNotBot = api.NotBot
)

// Result is what a lookup answers.
//
// A pointer member is one your plan does not include. It never means "we could
// not check", so nil and false are genuinely different answers: nil is "not in
// your plan", false is "checked, and no". BoolValue collapses the two for
// callers who only want to know whether an address is flagged. The same holds
// inside a shared object, so Location.City is nil on Unlimited.
//
// A detail object that is present but empty means the flag above it is false. A
// populated one always carries every one of its keys, empty values included.
// Web is a list of the services seen, empty when IsWeb is false.
//
// Asn.Type, on a paid plan or the trial, keeps the non-optional string it had
// until the next major: on Unlimited it reads "", which is absent as well,
// though never nil. The middleware package reads it as absent.
type Result struct {
	// The answer as it was served, with the wire's own optionality intact. Its
	// fields are promoted, so r.IsVpn and r.Vpn read straight off the Result.
	LookupResponse

	// True for reserved space (private, loopback, documentation and the like),
	// which this package answers locally without a request. A served answer
	// carries the API's own is_bogon, and this reads it.
	IsBogon bool `json:"is_bogon"`

	// The wire paths of the members the answer left out that LookupResponse
	// cannot show as nil, which the middleware package reads through held. A
	// Result built by hand has none, so all of them read as served.
	unserved []string
}

func init() {
	held.Unserved = func(result any) []string {
		if r, ok := result.(*Result); ok && r != nil {
			return r.unserved
		}
		return nil
	}
}

// BoolValue returns the value of the bool pointer passed in, or false if the
// pointer is nil.
//
// Go has no `??`, so this is how a caller who only wants to know whether an
// address is flagged reads a tier-gated member: BoolValue(r.IsHosting). Read
// the pointer itself wherever absent and false must be told apart, which is the
// whole reason these are pointers. Same name and behavior as stripe-go's
// helper of the same name, so it should already be familiar.
func BoolValue(v *bool) bool {
	if v != nil {
		return *v
	}
	return false
}
