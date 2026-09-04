// The Go-specific API surface, as distinct from the shared conformance corpus
// in conformance_test.go.

package vpndetection

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"
)

var manyAddrs = func() []string {
	addrs := make([]string, 12)
	for i := range addrs {
		addrs[i] = fmt.Sprintf("9.9.9.%d", i+1)
	}
	return addrs
}()

// Peak in-flight is the only measurement that tells a real limit from an option
// that was accepted and ignored.
func TestBatchConcurrencyIsConfigurablePerCall(t *testing.T) {
	stub := newStub(okRoutes(manyAddrs...))
	stub.delay = 20 * time.Millisecond
	client := newTestClient(t, stub, WithoutCache())

	if _, err := client.LookupBatch(t.Context(), manyAddrs, Concurrency(3)); err != nil {
		t.Fatalf("LookupBatch: %v", err)
	}

	if stub.count() != len(manyAddrs) {
		t.Errorf("issued %d request(s), want %d", stub.count(), len(manyAddrs))
	}
	if peak := stub.peakInFlight(); peak > 3 {
		t.Errorf("peak in flight was %d, want at most 3", peak)
	}
	if peak := stub.peakInFlight(); peak <= 1 {
		t.Errorf("peak in flight was %d, so requests never overlapped", peak)
	}
}

func TestAPerCallConcurrencyOverridesTheClientDefault(t *testing.T) {
	stub := newStub(okRoutes(manyAddrs...))
	stub.delay = 20 * time.Millisecond
	client := newTestClient(t, stub, WithoutCache(), WithConcurrency(2))

	if _, err := client.LookupBatch(t.Context(), manyAddrs, Concurrency(6)); err != nil {
		t.Fatalf("LookupBatch: %v", err)
	}

	peak := stub.peakInFlight()
	if peak <= 2 {
		t.Errorf("override ignored: peak in flight was %d, want above 2", peak)
	}
	if peak > 6 {
		t.Errorf("peak in flight was %d, want at most 6", peak)
	}
}

func TestWithoutAnOverrideTheClientConcurrencyStillApplies(t *testing.T) {
	stub := newStub(okRoutes(manyAddrs...))
	stub.delay = 20 * time.Millisecond
	client := newTestClient(t, stub, WithoutCache(), WithConcurrency(2))

	if _, err := client.LookupBatch(t.Context(), manyAddrs); err != nil {
		t.Fatalf("LookupBatch: %v", err)
	}

	if peak := stub.peakInFlight(); peak > 2 {
		t.Errorf("peak in flight was %d, want at most 2", peak)
	}
}

func TestRetriesAreConfigurablePerCall(t *testing.T) {
	stub := newStub(map[string]stubRoute{
		"9.9.9.9": {status: http.StatusInternalServerError, body: map[string]string{"error": "lookup failed"}},
	})
	client := newTestClient(t, stub, WithoutCache(), WithRetries(0))

	if _, err := client.Lookup(t.Context(), "9.9.9.9", Retries(2)); err == nil {
		t.Fatal("a 500 should have failed the lookup")
	}
	// One initial attempt plus two retries, rather than the client's zero.
	if stub.count() != 3 {
		t.Errorf("issued %d request(s), want 3", stub.count())
	}
}

// A 429 with no Retry-After is a spent allowance, and retrying it is hammering
// a quota that will not recover until its window rolls over.
func TestASpentQuotaIsNeverRetried(t *testing.T) {
	stub := newStub(map[string]stubRoute{
		"9.9.9.9": {
			status: http.StatusTooManyRequests,
			body:   map[string]string{"error": "request allowance exceeded"},
		},
	})
	client := newTestClient(t, stub, WithoutCache(), WithRetries(5))

	_, err := client.Lookup(t.Context(), "9.9.9.9")
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Kind != KindQuotaExceeded {
		t.Fatalf("error was %v, want a quota_exceeded *Error", err)
	}
	if stub.count() != 1 {
		t.Errorf("issued %d request(s), want 1", stub.count())
	}
}

func TestARateLimitIsRetriedAfterTheServerSuppliedWait(t *testing.T) {
	stub := newStub(map[string]stubRoute{
		"9.9.9.9": {
			status:  http.StatusTooManyRequests,
			body:    map[string]string{"error": "rate limit exceeded"},
			headers: map[string]string{"Retry-After": "1"},
		},
	})
	client := newTestClient(t, stub, WithoutCache(), WithRetries(1))

	start := time.Now()
	if _, err := client.Lookup(t.Context(), "9.9.9.9"); err == nil {
		t.Fatal("the lookup should still have failed after its retry")
	}
	if stub.count() != 2 {
		t.Errorf("issued %d request(s), want 2", stub.count())
	}
	// The header, not the backoff schedule, decides the wait.
	if waited := time.Since(start); waited < time.Second {
		t.Errorf("waited %s before retrying, want at least the 1s Retry-After", waited)
	}
}

func TestIsBogonIsOnTheClientAndAgreesWithTheStandaloneFunction(t *testing.T) {
	client := newTestClient(t, newStub(nil))
	for _, c := range corpus(t).IsBogon {
		if got := client.IsBogon(c.IP); got != c.Expect {
			t.Errorf("client.IsBogon(%q) = %v, want %v (%s)", c.IP, got, c.Expect, c.Why)
		}
		if client.IsBogon(c.IP) != IsBogon(c.IP) {
			t.Errorf("%s: the client and the standalone function disagree", c.IP)
		}
	}
}

// Go has no `??`, so these readers are the only ergonomic way to ask "flagged
// or not" without losing the absent-versus-false distinction elsewhere.
func TestBoolValueCoalescesAnAbsentFlag(t *testing.T) {
	absent := &Result{}
	if BoolValue(absent.IsHosting) || BoolValue(absent.IsDcproxy) {
		t.Error("an absent flag should read as false")
	}
	if absent.IsHosting != nil {
		t.Error("the reader must not populate the field it reads")
	}

	present := &Result{LookupResponse: LookupResponse{IsHosting: ptr(true), IsTor: ptr(false)}}
	if !BoolValue(present.IsHosting) {
		t.Error("a present true flag should read as true")
	}
	if BoolValue(present.IsTor) {
		t.Error("a present false flag should read as false")
	}
}

func TestDownloadURLReturnsTheRedirectRatherThanFollowingIt(t *testing.T) {
	const location = "https://s3.example.test/vpn_ip_extended_v1.mmdb?signature=abc"
	stub := newStub(map[string]stubRoute{
		"/api/v1/database/download": {
			status:  http.StatusFound,
			headers: map[string]string{"Location": location},
		},
	})
	client := newTestClient(t, stub, WithAPIKey("key"))

	url, err := client.Database.DownloadURL(t.Context(), "vpn_ip_extended_v1", FormatMMDB)
	if err != nil {
		t.Fatalf("DownloadURL: %v", err)
	}
	if url != location {
		t.Errorf("DownloadURL = %q, want %q", url, location)
	}
	// Following it would have streamed the dataset itself into memory.
	if stub.count() != 1 {
		t.Errorf("issued %d request(s), want 1", stub.count())
	}
}

func TestNewRejectsUnusableOptions(t *testing.T) {
	cases := []struct {
		name   string
		option Option
	}{
		{"zero concurrency", WithConcurrency(0)},
		{"negative retries", WithRetries(-1)},
		{"empty cache", WithCache(0, time.Hour)},
		{"expired cache", WithCache(10, 0)},
		{"nil http client", WithHTTPClient(nil)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := New(c.option); err == nil {
				t.Error("New should have rejected the option")
			}
		})
	}
}
