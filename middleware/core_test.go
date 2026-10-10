// Pins the client New builds when the caller passes none, which is how every
// framework README sets the middleware up.

package middleware_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/vpndetection-io/sdk-go/v5/middleware"
)

// Outside every bogon block, RFC 5737's documentation ranges included, so the
// lookup cannot be answered locally and has to reach the origin.
const publicIP = "9.9.9.9"

func selectorOf(ip string) middleware.IPSelector[string] {
	return func(string) string { return ip }
}

func TestNewStartsWithOnlyAnAPIKey(t *testing.T) {
	if _, err := middleware.New(middleware.Options[string]{APIKey: "key"}, selectorOf(publicIP)); err != nil {
		t.Fatalf("New with only an APIKey: %v", err)
	}
}

func TestNewStartsWithNoOptions(t *testing.T) {
	if _, err := middleware.New(middleware.Options[string]{}, selectorOf(publicIP)); err != nil {
		t.Fatalf("New with no options: %v", err)
	}
}

func TestNewSendsToTheBaseURL(t *testing.T) {
	var requests atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ip":"9.9.9.9","is_vpn":false}`)
	}))
	defer origin.Close()
	core, err := middleware.New(middleware.Options[string]{APIKey: "key", BaseURL: origin.URL}, selectorOf(publicIP))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	lookup, err := core.Evaluate(t.Context(), "request")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if lookup.Err != nil {
		t.Fatalf("lookup failed: %v", lookup.Err)
	}
	if got := requests.Load(); got != 1 {
		t.Errorf("the origin got %d requests, want 1", got)
	}
}

func TestNewRefusesABaseURLWithNoScheme(t *testing.T) {
	if _, err := middleware.New(middleware.Options[string]{BaseURL: "api.vpndetection.io"}, selectorOf(publicIP)); err == nil {
		t.Error("New accepted a base URL with no scheme")
	}
}
