package vpndetection

import (
	"fmt"
	"net/netip"
	"sync"
)

// IsBogon reports whether an address is private, loopback, link-local,
// documentation, multicast or otherwise not routable on the public internet,
// including the IPv6 equivalents and the 6to4 and Teredo ranges that wrap them.
//
// These can never be VPN or proxy infrastructure, so the client answers them
// itself and they never cost a request. Client.IsBogon is the same check, for
// code that already holds a client.
func IsBogon(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	prefixes := bogonPrefixesV6
	if addr.Is4() {
		prefixes = bogonPrefixesV4
	}
	for _, prefix := range prefixes() {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// The answer a bogon gets: the full shape the API serves on its widest plan,
// every flag present and false and every detail object present and empty, plus
// the IsBogon marker that tells a computed answer from a served one.
//
// Deliberately the WIDEST shape whatever plan you are on, so a caller must not
// infer which fields their plan includes from a bogon answer.
func bogonResult(ip string) *Result {
	return &Result{
		IsBogon: true,
		LookupResponse: LookupResponse{
			IP:         ip,
			IsVpn:      false,
			IsHosting:  ptr(false),
			IsRelay:    ptr(false),
			IsTor:      ptr(false),
			IsCdn:      ptr(false),
			IsResproxy: ptr(false),
			IsDcproxy:  ptr(false),
			IsMobproxy: ptr(false),
			Vpn:        &VpnDetail{},
			Hosting:    &ClassDetail{},
			Relay:      &ClassDetail{},
			Tor:        &ClassDetail{},
			Cdn:        &ClassDetail{},
			Resproxy:   &ProxyDetail{},
			Dcproxy:    &ProxyDetail{},
			Mobproxy:   &ProxyDetail{},
		},
	}
}

// Parsed on first use rather than at init, so importing the package costs
// nothing for a consumer that never looks an address up.
var (
	bogonPrefixesV4 = sync.OnceValue(func() []netip.Prefix { return parsePrefixes(bogonV4) })
	bogonPrefixesV6 = sync.OnceValue(func() []netip.Prefix { return parsePrefixes(bogonV6) })
)

// The table is generated and checked upstream, and TestBogonTableParses asserts
// every entry here, so an unparseable one is a broken build rather than
// something a caller can hit.
func parsePrefixes(cidrs []string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			panic(fmt.Sprintf("vpndetection: unparseable bogon range %q: %v", cidr, err))
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

func ptr[T any](v T) *T {
	return &v
}
