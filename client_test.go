// The Go-specific API surface, as distinct from the shared conformance corpus
// in conformance_test.go.

package vpndetection

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// Enough addresses for seven chunks of the batch endpoint's 1000, so a
// concurrency bound has something to bound: one request per chunk, and only
// the chunks overlap.
var manyAddrs = func() []string {
	addrs := make([]string, 6001)
	for i := range addrs {
		addrs[i] = fmt.Sprintf("9.%d.%d.%d", 1+i/65536, (i/256)%256, i%256)
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

	if stub.count() != 7 {
		t.Errorf("issued %d request(s), want 7 chunks for %d addresses", stub.count(), len(manyAddrs))
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

// errgroup reads a limit of 0 as admitting nothing, so an unrefused
// Concurrency(0) waited forever, deaf even to its context.
func TestABatchRefusesAConcurrencyBelowOneBeforeAnyRequest(t *testing.T) {
	for _, n := range []int{0, -1} {
		stub := newStub(okRoutes("9.9.9.9"))
		client := newTestClient(t, stub, WithoutCache())

		got, err := client.LookupBatch(t.Context(), []string{"9.9.9.9"}, Concurrency(n))
		var apiErr *Error
		if !errors.As(err, &apiErr) || apiErr.Kind != KindBadRequest || got != nil {
			t.Fatalf("Concurrency(%d): got %v, %v; want a bad_request *Error", n, got, err)
		}
		if stub.count() != 0 {
			t.Errorf("Concurrency(%d): issued %d request(s), want none", n, stub.count())
		}
	}
}

// The per-call Timeout has to be the bound that fires, not the client's, and it
// has to fail as every transport failure does. Retries(1) makes it per ATTEMPT:
// a deadline over the whole call would expire during the backoff and never send
// the second request.
func TestAPerCallTimeoutBoundsEachAttemptBelowTheClients(t *testing.T) {
	cases := []struct {
		name string
		call func(context.Context, *Client, ...LookupOption) error
	}{
		{"Lookup", func(ctx context.Context, c *Client, opts ...LookupOption) error {
			_, err := c.Lookup(ctx, "9.9.9.9", opts...)
			return err
		}},
		{"MyIP", func(ctx context.Context, c *Client, opts ...LookupOption) error {
			_, err := c.MyIP(ctx, opts...)
			return err
		}},
		{"MyEntitlement", func(ctx context.Context, c *Client, opts ...LookupOption) error {
			_, err := c.MyEntitlement(ctx, opts...)
			return err
		}},
		{"LookupBatch", func(ctx context.Context, c *Client, opts ...LookupOption) error {
			batchOpts := make([]BatchOption, len(opts))
			for i, opt := range opts {
				batchOpts[i] = opt
			}
			got, err := c.LookupBatch(ctx, []string{"9.9.9.9"}, batchOpts...)
			if err != nil {
				return err
			}
			return got["9.9.9.9"].Err
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			api := newSlowAPI(t, 0)
			client, err := New(WithBaseURL(api.URL), WithoutCache(),
				WithHTTPClient(&http.Client{Timeout: 5 * time.Second}))
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			start := time.Now()
			err = c.call(t.Context(), client, Timeout(100*time.Millisecond), Retries(1))
			elapsed := time.Since(start)

			var apiErr *Error
			if !errors.As(err, &apiErr) || apiErr.Kind != KindNetwork || !apiErr.Retryable() {
				t.Fatalf("error was %v, want a retryable network *Error", err)
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("error was %v, want one that reports a deadline", err)
			}
			if n := api.requests.Load(); n != 2 {
				t.Errorf("sent %d request(s), want 2: each attempt gets the whole timeout", n)
			}
			if elapsed > 2500*time.Millisecond {
				t.Errorf("gave up after %s, so the client's 5s bound fired rather than the call's", elapsed)
			}
		})
	}
}

// The override replaces the client's bound rather than racing it, so a call
// that is expected to be slow can be given longer than the client allows.
func TestAPerCallTimeoutCanLoosenTheClients(t *testing.T) {
	api := newSlowAPI(t, 300*time.Millisecond)
	client, err := New(WithBaseURL(api.URL), WithoutCache(), WithRetries(0),
		WithHTTPClient(&http.Client{Timeout: 50 * time.Millisecond}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := client.Lookup(t.Context(), "9.9.9.9"); err == nil {
		t.Fatal("a 300ms answer should have outlasted the client's 50ms")
	}
	result, err := client.Lookup(t.Context(), "9.9.9.9", Timeout(5*time.Second))
	if err != nil {
		t.Fatalf("Lookup with a 5s timeout: %v", err)
	}
	if result.IP != "9.9.9.9" {
		t.Errorf("IP = %q, want 9.9.9.9", result.IP)
	}
}

// An API that answers every request after a delay, or with a zero delay never:
// it holds each request until the client abandons it. A real server rather
// than the stub transport, because a timeout is only honest against a transport
// that honors cancellation.
type slowAPI struct {
	*httptest.Server
	requests atomic.Int32
}

func newSlowAPI(t *testing.T, delay time.Duration) *slowAPI {
	t.Helper()
	api := &slowAPI{}
	release := make(chan struct{})
	api.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.requests.Add(1)
		// Draining the body is what lets the server notice the client leave.
		_, _ = io.Copy(io.Discard, r.Body)
		var answer <-chan time.Time
		if delay > 0 {
			answer = time.After(delay)
		}
		select {
		case <-answer:
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ip":"9.9.9.9","is_vpn":false}`)
		case <-r.Context().Done():
		case <-release:
		}
	}))
	// Cleanups run last-in first-out, so the held handlers return before Close
	// waits on them.
	t.Cleanup(api.Close)
	t.Cleanup(func() { close(release) })
	return api
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

func TestMyIPAsksTheServerWhichAddressYouAre(t *testing.T) {
	stub := newStub(map[string]stubRoute{
		"myip": {body: map[string]any{"ip": "203.0.113.9", "is_vpn": true}},
	})
	client := newTestClient(t, stub)

	result, err := client.MyIP(t.Context())
	if err != nil {
		t.Fatalf("MyIP: %v", err)
	}
	if result.IP != "203.0.113.9" {
		t.Errorf("got %q, want 203.0.113.9", result.IP)
	}
	if !result.IsVpn {
		t.Error("is_vpn did not survive")
	}
}

// The cache is keyed by ADDRESS, and which address this is IS the question, so
// a second call has to ask again. A laptop that moved networks would otherwise
// be told where it used to be.
func TestMyIPIsNotCached(t *testing.T) {
	stub := newStub(map[string]stubRoute{
		"myip": {body: map[string]any{"ip": "203.0.113.9", "is_vpn": false}},
	})
	client := newTestClient(t, stub)

	for i := 0; i < 3; i++ {
		if _, err := client.MyIP(t.Context()); err != nil {
			t.Fatalf("MyIP: %v", err)
		}
	}
	if stub.count() != 3 {
		t.Errorf("issued %d request(s), want 3 - the answer was cached", stub.count())
	}
}

func TestMyIPSurfacesAnError(t *testing.T) {
	stub := newStub(map[string]stubRoute{
		"myip": {status: 401, body: map[string]string{"error": "invalid API key"}},
	})
	client := newTestClient(t, stub)

	_, err := client.MyIP(t.Context())
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Kind != KindUnauthorized {
		t.Fatalf("got %v, want an unauthorized *Error", err)
	}
}

func TestMyEntitlementReportsThePlanAndTheUsage(t *testing.T) {
	stub := newStub(map[string]stubRoute{
		"/api/v1/entitlement": {body: map[string]any{
			"org_id": "85bb51e4-2eb6-4a31-8e4d-02ba8b98fe61",
			"apikey": map[string]any{"id": "0ab424cc-7619-4dad-b027-afacdc2cedb0", "expires": nil, "allowed_cidrs": []string{}},
			"plan":   map[string]any{"key": "max", "tier": "max"},
			"usage": map[string]any{
				"requests": 580, "quota": 5000000, "hard_limit": nil,
				"window_start": "2026-09-04T07:00:00Z", "window_end": "2026-10-04T07:00:00Z",
			},
		}},
	})
	client := newTestClient(t, stub)

	acct, err := client.MyEntitlement(t.Context())
	if err != nil {
		t.Fatalf("MyEntitlement: %v", err)
	}
	if acct.Plan.Key != "max" {
		t.Errorf("plan = %q, want max", acct.Plan.Key)
	}
	if acct.Usage.Requests != 580 {
		t.Errorf("requests = %d, want 580", acct.Usage.Requests)
	}
	// An uncapped plan reports NULL, which is not zero: zero would read as
	// "stop serving immediately".
	if acct.Usage.HardLimit != nil {
		t.Errorf("hard_limit = %v, want nil for an uncapped plan", *acct.Usage.HardLimit)
	}
}

// Usage is the whole point, so a cached answer is a wrong one within seconds.
func TestMyEntitlementIsNotCached(t *testing.T) {
	stub := newStub(map[string]stubRoute{
		"/api/v1/entitlement": {body: map[string]any{
			"org_id": "f32191d0-ef02-450e-a505-eb5814c35cab", "apikey": map[string]any{"id": "10c2b437-3aa2-4a63-bd17-8e7c8c7f0def", "expires": nil, "allowed_cidrs": []string{}},
			"plan":  map[string]any{"key": "free", "tier": "free"},
			"usage": map[string]any{"requests": 1, "quota": 2, "hard_limit": 2, "window_start": "2026-09-01T00:00:00Z", "window_end": "2026-10-01T00:00:00Z"},
		}},
	})
	client := newTestClient(t, stub)
	for i := 0; i < 3; i++ {
		if _, err := client.MyEntitlement(t.Context()); err != nil {
			t.Fatalf("MyEntitlement: %v", err)
		}
	}
	if stub.count() != 3 {
		t.Errorf("issued %d request(s), want 3 - the answer was cached", stub.count())
	}
}
