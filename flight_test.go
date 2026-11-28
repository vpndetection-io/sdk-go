package vpndetection

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"
)

// Long enough that a call started a quarter of it later is still concurrent.
const stagger = 400 * time.Millisecond

func (s *stubTransport) sent() ([]string, [][]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.calls), slices.Clone(s.batched)
}

// A middleware looks the visitor up on every request a page fires, all at once,
// so concurrent misses for one address must share one request.
func TestConcurrentMissesForOneAddressShareOneRequest(t *testing.T) {
	stub := newStub(okRoutes("45.83.91.1"))
	stub.delay = 200 * time.Millisecond
	client := newTestClient(t, stub)

	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for range 20 {
		wg.Go(func() {
			result, err := client.Lookup(t.Context(), "45.83.91.1")
			if err == nil && result.IP != "45.83.91.1" {
				err = errors.New("answered " + result.IP)
			}
			errs <- err
		})
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Errorf("a caller: %v", err)
		}
	}
	if n := stub.count(); n != 1 {
		t.Errorf("20 concurrent callers sent %d requests, want 1", n)
	}
}

// A failure is handed to every caller waiting on it and cached for none, so the
// next call asks again.
func TestASharedFailureReachesEveryWaiterAndIsNotCached(t *testing.T) {
	stub := newStub(map[string]stubRoute{
		"45.83.91.1": {status: http.StatusForbidden, body: map[string]string{"error": "forbidden"}},
	})
	stub.delay = 200 * time.Millisecond
	client := newTestClient(t, stub, WithRetries(0))

	var wg sync.WaitGroup
	errs := make(chan error, 5)
	for range 5 {
		wg.Go(func() {
			_, err := client.Lookup(t.Context(), "45.83.91.1")
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		var apiErr *Error
		if !errors.As(err, &apiErr) || apiErr.Kind != KindForbidden {
			t.Errorf("a waiter got %v, want the one forbidden answer", err)
		}
	}
	if n := stub.count(); n != 1 {
		t.Fatalf("sent %d requests, want 1", n)
	}

	stub.mu.Lock()
	stub.routes["45.83.91.1"] = stubRoute{body: map[string]any{"ip": "45.83.91.1", "is_vpn": true}}
	stub.mu.Unlock()
	result, err := client.Lookup(t.Context(), "45.83.91.1")
	if err != nil || !result.IsVpn {
		t.Fatalf("asked again: %v %v", result, err)
	}
	if n := stub.count(); n != 2 {
		t.Errorf("sent %d requests, want 2: the failure was cached", n)
	}
}

// A batch awaits the lookup already in flight for one of its addresses rather
// than sending that address again.
func TestABatchAwaitsALookupInFlight(t *testing.T) {
	stub := newStub(okRoutes("45.83.91.1", "45.83.91.2"))
	stub.delay = stagger
	client := newTestClient(t, stub)

	var wg sync.WaitGroup
	wg.Go(func() {
		if _, err := client.Lookup(t.Context(), "45.83.91.1"); err != nil {
			t.Errorf("Lookup: %v", err)
		}
	})
	time.Sleep(stagger / 4)
	got, err := client.LookupBatch(t.Context(), []string{"45.83.91.1", "45.83.91.2"})
	wg.Wait()

	if err != nil || got["45.83.91.1"].Err != nil || got["45.83.91.2"].Err != nil {
		t.Fatalf("LookupBatch: %v %+v", err, got)
	}
	calls, batched := stub.sent()
	if len(calls) != 2 || len(batched) != 1 || !slices.Equal(batched[0], []string{"45.83.91.2"}) {
		t.Errorf("sent %v with bodies %v, want the lookup and a batch of 45.83.91.2 alone", calls, batched)
	}
}

// A lookup awaits the batch in flight that carries its address.
func TestALookupAwaitsABatchInFlight(t *testing.T) {
	stub := newStub(okRoutes("45.83.91.1", "45.83.91.2"))
	stub.delay = stagger
	client := newTestClient(t, stub)

	var wg sync.WaitGroup
	wg.Go(func() {
		if _, err := client.LookupBatch(t.Context(), []string{"45.83.91.1", "45.83.91.2"}); err != nil {
			t.Errorf("LookupBatch: %v", err)
		}
	})
	time.Sleep(stagger / 4)
	result, err := client.Lookup(t.Context(), "45.83.91.2")
	wg.Wait()

	if err != nil || result.IP != "45.83.91.2" {
		t.Fatalf("Lookup: %v %v", result, err)
	}
	if n := stub.count(); n != 1 {
		t.Errorf("sent %d requests, want the batch alone", n)
	}
}

// A lookup that joined a batch takes the batch's answer for its address, a
// failed one included, which the cache never holds for it to fall back on.
func TestALookupTakesTheFailureOfTheBatchItJoined(t *testing.T) {
	routes := okRoutes("45.83.91.1")
	routes["45.83.91.2"] = stubRoute{status: http.StatusForbidden, body: map[string]string{"error": "forbidden"}}
	stub := newStub(routes)
	stub.delay = stagger
	client := newTestClient(t, stub)

	var wg sync.WaitGroup
	wg.Go(func() { _, _ = client.LookupBatch(t.Context(), []string{"45.83.91.1", "45.83.91.2"}) })
	time.Sleep(stagger / 4)
	_, err := client.Lookup(t.Context(), "45.83.91.2")
	wg.Wait()

	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Kind != KindForbidden {
		t.Errorf("Lookup: %v, want the batch's forbidden answer", err)
	}
	if n := stub.count(); n != 1 {
		t.Errorf("sent %d requests, want the batch alone", n)
	}
}

// The request runs detached from the caller that led it, so that caller giving
// up returns at once and fails nobody waiting on it.
func TestACallerGivingUpFailsNobodyElse(t *testing.T) {
	stub := newStub(okRoutes("45.83.91.1", "45.83.91.2"))
	stub.delay = stagger
	client := newTestClient(t, stub)

	short, cancel := context.WithTimeout(t.Context(), stagger/2)
	defer cancel()
	var wg sync.WaitGroup
	var result *Result
	var err error
	wg.Go(func() {
		time.Sleep(stagger / 4)
		result, err = client.Lookup(t.Context(), "45.83.91.1")
	})
	start := time.Now()
	_, gaveUp := client.Lookup(short, "45.83.91.1")
	took := time.Since(start)
	wg.Wait()

	if !errors.Is(gaveUp, context.DeadlineExceeded) || took > stagger*3/4 {
		t.Errorf("the leader returned %v after %s, want its own deadline at once", gaveUp, took)
	}
	if err != nil || result.IP != "45.83.91.1" {
		t.Errorf("the waiter got %v %v, want the answer", result, err)
	}

	// A batch given up part way fails no lookup that joined it either.
	short, cancel = context.WithTimeout(t.Context(), stagger/2)
	defer cancel()
	wg.Go(func() {
		time.Sleep(stagger / 4)
		result, err = client.Lookup(t.Context(), "45.83.91.2")
	})
	got, batchErr := client.LookupBatch(short, []string{"45.83.91.2"})
	wg.Wait()
	if !errors.Is(batchErr, context.DeadlineExceeded) || !errors.Is(got["45.83.91.2"].Err, context.DeadlineExceeded) {
		t.Errorf("the batch returned %v %+v, want its own deadline", batchErr, got)
	}
	if err != nil || result.IP != "45.83.91.2" {
		t.Errorf("the lookup that joined the batch got %v %v, want the answer", result, err)
	}
	if n := stub.count(); n != 2 {
		t.Errorf("sent %d requests, want one per address", n)
	}
}

// Without a cache every lookup is served, as WithoutCache promises.
func TestAClientWithoutACacheSharesNothing(t *testing.T) {
	stub := newStub(okRoutes("45.83.91.1"))
	stub.delay = 100 * time.Millisecond
	client := newTestClient(t, stub, WithoutCache())

	var wg sync.WaitGroup
	for range 3 {
		wg.Go(func() { _, _ = client.Lookup(t.Context(), "45.83.91.1") })
	}
	for range 2 {
		wg.Go(func() { _, _ = client.LookupBatch(t.Context(), []string{"45.83.91.1"}) })
	}
	wg.Wait()

	if n := stub.count(); n != 5 {
		t.Errorf("sent %d requests, want 5", n)
	}
}

// Answers 429 with a Retry-After for its first requests, then serves what the
// stub does: an origin that is throttling and then recovers.
type throttle struct {
	*stubTransport
	mu         sync.Mutex
	left       int
	retryAfter string
}

func (th *throttle) RoundTrip(req *http.Request) (*http.Response, error) {
	th.mu.Lock()
	throttled := th.left > 0
	th.left--
	th.mu.Unlock()
	if !throttled {
		return th.stubTransport.RoundTrip(req)
	}
	th.enter(req.URL.String())
	th.leave()
	return th.respond(req, stubRoute{
		status:  http.StatusTooManyRequests,
		body:    map[string]string{"error": "slow down"},
		headers: map[string]string{"Retry-After": th.retryAfter},
	}), nil
}

func (th *throttle) recover() {
	th.mu.Lock()
	defer th.mu.Unlock()
	th.left = 0
}

// The longest Retry-After the client waits out as given, in whole seconds.
const longestRetryAfter = "2147483"

func newThrottledClient(t *testing.T, th *throttle) *Client {
	t.Helper()
	client, err := New(WithHTTPClient(&http.Client{Transport: th}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

// A request retrying on a long Retry-After sleeps detached from every caller,
// so once the one awaiting it gives up nobody is left to wake it: the next
// caller for the address joined a sleep of days, and timed out however fast the
// origin had recovered.
func TestAFlightNobodyAwaitsStopsWaitingOutARetryAfter(t *testing.T) {
	const ip = "45.83.91.1"
	for _, second := range []string{"Lookup", "LookupBatch"} {
		t.Run(second, func(t *testing.T) {
			th := &throttle{stubTransport: newStub(okRoutes(ip)), left: 1 << 30, retryAfter: longestRetryAfter}
			client := newThrottledClient(t, th)

			short, cancel := context.WithTimeout(t.Context(), stagger/2)
			defer cancel()
			if _, err := client.Lookup(short, ip); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("the first caller got %v, want its own deadline", err)
			}
			th.recover()

			ctx, cancelSecond := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancelSecond()
			start := time.Now()
			var err error
			if second == "Lookup" {
				var result *Result
				result, err = client.Lookup(ctx, ip)
				if err == nil && result.IP != ip {
					err = errors.New("answered " + result.IP)
				}
			} else {
				var got map[string]BatchResult
				got, err = client.LookupBatch(ctx, []string{ip})
				if err == nil {
					err = got[ip].Err
				}
			}
			if err != nil {
				t.Fatalf("%s after the origin recovered: %v", second, err)
			}
			if took := time.Since(start); took > 2*time.Second {
				t.Errorf("%s took %s once the origin had recovered", second, took)
			}
			if _, err := client.Lookup(t.Context(), ip); err != nil {
				t.Errorf("Lookup of the cached answer: %v", err)
			}
			if n := th.count(); n != 2 {
				t.Errorf("sent %d requests, want the throttled one and the recovered one", n)
			}
		})
	}
}

// A batch's chunk sleeps the same way, and a lookup joining one of its
// addresses is the caller that finds it asleep.
func TestAChunkNobodyAwaitsStopsWaitingOutARetryAfter(t *testing.T) {
	routes := okRoutes("45.83.91.1", "45.83.91.2")
	th := &throttle{stubTransport: newStub(routes), left: 1 << 30, retryAfter: longestRetryAfter}
	client := newThrottledClient(t, th)

	short, cancel := context.WithTimeout(t.Context(), stagger/2)
	defer cancel()
	if _, err := client.LookupBatch(short, []string{"45.83.91.1", "45.83.91.2"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the batch returned %v, want its own deadline", err)
	}
	th.recover()

	ctx, cancelLookup := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancelLookup()
	result, err := client.Lookup(ctx, "45.83.91.2")
	if err != nil || result.IP != "45.83.91.2" {
		t.Fatalf("Lookup after the origin recovered: %v %v", result, err)
	}
	if n := th.count(); n != 2 {
		t.Errorf("sent %d requests, want the throttled batch and the lookup", n)
	}
}

// A request given up on is stopped, not left asleep to send its retry a Retry-After
// later for an address nobody is waiting on.
func TestAGivenUpFlightSendsNoRetry(t *testing.T) {
	const ip = "45.83.91.1"
	th := &throttle{stubTransport: newStub(okRoutes(ip)), left: 1, retryAfter: "1"}
	client := newThrottledClient(t, th)

	short, cancel := context.WithTimeout(t.Context(), stagger/2)
	defer cancel()
	if _, err := client.Lookup(short, ip); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the caller got %v, want its own deadline", err)
	}
	time.Sleep(1300 * time.Millisecond)

	if n := th.count(); n != 1 {
		t.Errorf("sent %d requests, want the throttled one alone: the given up request retried", n)
	}
}

// One caller still waiting keeps the request retrying, whoever led it.
func TestACallerStillWaitingKeepsTheRetryOfAFlightItJoined(t *testing.T) {
	const ip = "45.83.91.1"
	th := &throttle{stubTransport: newStub(okRoutes(ip)), left: 1, retryAfter: "1"}
	client := newThrottledClient(t, th)

	short, cancel := context.WithTimeout(t.Context(), stagger/2)
	defer cancel()
	var wg sync.WaitGroup
	var result *Result
	var err error
	start := time.Now()
	wg.Go(func() {
		time.Sleep(stagger / 8)
		result, err = client.Lookup(t.Context(), ip)
	})
	if _, gaveUp := client.Lookup(short, ip); !errors.Is(gaveUp, context.DeadlineExceeded) {
		t.Errorf("the leader got %v, want its own deadline", gaveUp)
	}
	wg.Wait()

	if err != nil || result.IP != ip {
		t.Fatalf("the caller still waiting got %v %v, want the answer after the retry", result, err)
	}
	if took := time.Since(start); took < 900*time.Millisecond {
		t.Errorf("answered after %s, want the Retry-After of 1s waited out", took)
	}
	if n := th.count(); n != 2 {
		t.Errorf("sent %d requests, want the throttled one and its retry", n)
	}
}

// Only a wait is given up on: a request under way when its one caller leaves
// finishes and is cached, so the next call is answered without sending.
func TestARequestUnderWayWhenItsCallerLeavesIsStillCached(t *testing.T) {
	const ip = "45.83.91.1"
	stub := newStub(okRoutes(ip))
	stub.delay = stagger
	client := newTestClient(t, stub)

	short, cancel := context.WithTimeout(t.Context(), stagger/4)
	defer cancel()
	if _, err := client.Lookup(short, ip); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the caller got %v, want its own deadline", err)
	}
	time.Sleep(stagger)

	result, err := client.Lookup(t.Context(), ip)
	if err != nil || result.IP != ip {
		t.Fatalf("Lookup: %v %v", result, err)
	}
	if n := stub.count(); n != 1 {
		t.Errorf("sent %d requests, want the one the first caller left running", n)
	}
}
