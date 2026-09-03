// A smoke test against the real API, skipped unless VPNDETECTION_LIVE=1 so a
// normal `go test` stays offline and costs no quota. Set VPNDETECTION_API_KEY
// to exercise a paid plan's fields; without one it runs on the free tier.
//
//	VPNDETECTION_LIVE=1 go test -run TestLive -v ./...

package vpndetection

import (
	"os"
	"testing"
)

func TestLiveLookup(t *testing.T) {
	if os.Getenv("VPNDETECTION_LIVE") != "1" {
		t.Skip("set VPNDETECTION_LIVE=1 to query the real API")
	}
	var opts []Option
	if key := os.Getenv("VPNDETECTION_API_KEY"); key != "" {
		opts = append(opts, WithAPIKey(key))
	}
	client, err := New(opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	vpn, err := client.Lookup(t.Context(), "45.83.91.1")
	if err != nil {
		t.Fatalf("Lookup(45.83.91.1): %v", err)
	}
	t.Logf("45.83.91.1: IsVpn=%v IsBogon=%v IsHosting=%v Vpn=%+v",
		vpn.IsVpn, vpn.IsBogon, vpn.IsHosting, vpn.Vpn)
	if !vpn.IsVpn {
		t.Error("45.83.91.1 should be VPN infrastructure")
	}

	clean, err := client.Lookup(t.Context(), "1.1.1.1")
	if err != nil {
		t.Fatalf("Lookup(1.1.1.1): %v", err)
	}
	t.Logf("1.1.1.1: IsVpn=%v IsBogon=%v IsHosting=%v",
		clean.IsVpn, clean.IsBogon, clean.IsHosting)
	if clean.IsVpn {
		t.Error("1.1.1.1 should not be VPN infrastructure")
	}
	if os.Getenv("VPNDETECTION_API_KEY") == "" && clean.IsHosting != nil {
		t.Error("the free tier does not include is_hosting, so it must be absent")
	}
}
