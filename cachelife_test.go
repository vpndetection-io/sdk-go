// A spent trial's or a reached cap's answer changes as soon as the trial is
// renewed or the cap raised, so it is cached for a minute at most rather than
// for the client's TTL.

package vpndetection

import (
	"maps"
	"sync"
	"testing"
	"time"
)

var cacheLifeFlags = map[string]map[string]any{
	"45.83.91.1": nil,
	"45.83.91.2": {"trial_expired": false, "cap_reached": false},
	"45.83.91.3": {"trial_expired": true},
	"45.83.91.4": {"cap_reached": true},
}

func cacheLifeStub() *stubTransport {
	routes := make(map[string]stubRoute, len(cacheLifeFlags))
	for ip, flags := range cacheLifeFlags {
		body := map[string]any{"ip": ip, "is_vpn": false}
		maps.Copy(body, flags)
		routes[ip] = stubRoute{body: body}
	}
	return newStub(routes)
}

func TestEachAnswerIsCachedAsLongAsItsFlagsAllow(t *testing.T) {
	cases := []struct {
		ip        string
		ttl, want time.Duration
	}{
		{"45.83.91.1", time.Hour, time.Hour},
		{"45.83.91.2", time.Hour, time.Hour},
		{"45.83.91.3", time.Hour, time.Minute},
		{"45.83.91.4", time.Hour, time.Minute},
		{"45.83.91.3", 5 * time.Second, 5 * time.Second},
		{"45.83.91.4", 5 * time.Second, 5 * time.Second},
		{"45.83.91.1", 5 * time.Second, 5 * time.Second},
	}
	for _, how := range []string{"Lookup", "LookupBatch"} {
		for _, tc := range cases {
			client := newTestClient(t, cacheLifeStub(), WithCache(100, tc.ttl))

			before := time.Now()
			var err error
			if how == "Lookup" {
				_, err = client.Lookup(t.Context(), tc.ip)
			} else {
				_, err = client.LookupBatch(t.Context(), []string{tc.ip, "45.83.91.1"})
			}
			after := time.Now()
			if err != nil {
				t.Fatalf("%s(%s): %v", how, tc.ip, err)
			}

			held, ok := client.cache.lru.Peek(answerKey{ip: tc.ip})
			if !ok {
				t.Fatalf("%s: %s under a %s TTL was not cached", how, tc.ip, tc.ttl)
			}
			if held.expires.Before(before.Add(tc.want)) || held.expires.After(after.Add(tc.want)) {
				t.Errorf("%s: %s under a %s TTL expires %s after the call, want %s",
					how, tc.ip, tc.ttl, held.expires.Sub(before), tc.want)
			}
		}
	}
}

func TestAReducedAnswerIsStillCachedSoARepeatSendsNothing(t *testing.T) {
	stub := cacheLifeStub()
	client := newTestClient(t, stub)

	if _, err := client.Lookup(t.Context(), "45.83.91.3"); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	again, err := client.Lookup(t.Context(), "45.83.91.3")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !BoolValue(again.TrialExpired) {
		t.Errorf("TrialExpired = %v, want true", again.TrialExpired)
	}
	if stub.count() != 1 {
		t.Errorf("issued %d request(s), want 1", stub.count())
	}
}

func TestAReducedAnswerPastItsLifeIsAskedForAgain(t *testing.T) {
	stub := cacheLifeStub()
	client := newTestClient(t, stub)

	if _, err := client.Lookup(t.Context(), "45.83.91.4"); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	held, _ := client.cache.lru.Peek(answerKey{ip: "45.83.91.4"})
	held.expires = time.Now().Add(-time.Millisecond)
	client.cache.lru.Add(answerKey{ip: "45.83.91.4"}, held)
	if _, err := client.Lookup(t.Context(), "45.83.91.4"); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if stub.count() != 2 {
		t.Errorf("issued %d request(s), want 2 - a stale answer was served", stub.count())
	}
}

// The shorter life changes how long an answer is held, never how a miss is
// served: concurrent misses for a reduced answer still share one request.
func TestConcurrentMissesForAReducedAnswerShareOneRequest(t *testing.T) {
	stub := cacheLifeStub()
	stub.delay = 200 * time.Millisecond
	client := newTestClient(t, stub)

	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if _, err := client.Lookup(t.Context(), "45.83.91.4"); err != nil {
				t.Errorf("a caller: %v", err)
			}
		})
	}
	wg.Go(func() {
		if _, err := client.LookupBatch(t.Context(), []string{"45.83.91.4"}); err != nil {
			t.Errorf("the batch: %v", err)
		}
	})
	wg.Wait()

	if n := stub.count(); n != 1 {
		t.Errorf("20 lookups and a batch of one address sent %d requests, want 1", n)
	}
}
