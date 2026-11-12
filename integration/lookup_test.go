// The published module looking addresses up against the staging API.
//
// Nothing here pins a field COUNT. The tiers are asserted as a RELATION, each
// one serving a superset of the tier below it, so a pricing change stays a
// pricing change instead of arriving as a red SDK build. What a served answer
// must satisfy on every tier: ip and is_vpn always; a present flag is a real
// boolean; a field a higher tier serves is ABSENT on a lower one rather than
// false; a populated detail object carries its documented keys; an empty one
// means its flag is false.

package integration

import (
	"errors"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"testing"

	vpndetection "github.com/vpndetection-io/sdk-go/v5"
)

func TestALookupWithoutAKeyAnswersIPAndIsVpnAtTheLeast(t *testing.T) {
	f := answerFor(t, unauthRung())

	if f.raw["ip"] != probe {
		t.Errorf("the wire answered about %v, want %s", f.raw["ip"], probe)
	}
	if _, ok := f.raw["is_vpn"].(bool); !ok {
		t.Errorf("is_vpn is %v, want a boolean", f.raw["is_vpn"])
	}
	assertServedByTier(t, f)
	t.Logf("testing against %s", staging)
}

func TestAKeyReachesTheWireAndItsAnswerKeepsItsShape(t *testing.T) {
	for _, r := range rungs {
		if r.secret == "" {
			continue
		}
		t.Run(r.tier, func(t *testing.T) {
			if reason := r.skipReason(); reason != "" {
				t.Skip(reason)
			}
			assertServedByTier(t, answerFor(t, r))
		})
	}
}

func TestEachTierServesASupersetOfTheTierBelow(t *testing.T) {
	if reason := ladderSkip(); reason != "" {
		t.Skip(reason)
	}

	var below *fixture
	for _, r := range observableRungs() {
		f := answerFor(t, r)
		fields := tierFields(f.raw)
		t.Logf("%s: %d fields", r.tier, len(fields))
		if below == nil {
			below = f
			continue
		}
		lower := tierFields(below.raw)
		for field := range lower {
			if _, ok := fields[field]; !ok {
				t.Errorf("%s drops %s, which %s serves", r.tier, field, below.rung.tier)
			}
		}
		// Without this a run in which every key resolved to the same plan would
		// pass: identical sets satisfy containment in both directions.
		if r.widens && len(fields) <= len(lower) {
			t.Errorf("%s answers %d field(s) and %s answers %d, so it is no wider",
				r.tier, len(fields), below.rung.tier, len(lower))
		}
		if r.tier != "trial" {
			below = f
		}
	}
}

func TestAFreePlanKeysAnswerIsAPaidOneOrUnlimitedsAndSaysWhich(t *testing.T) {
	if reason := trialRung().skipReason(); reason != "" {
		t.Skip(reason)
	}
	raw := answerFor(t, trialRung()).raw

	expired, ok := raw["trial_expired"].(bool)
	if !ok {
		t.Fatalf("a free-plan key's answer carries trial_expired %v, want a boolean", raw["trial_expired"])
	}
	// The organization's first 100 lookups of the UTC day are answered in full,
	// and the rest as Unlimited's: which half a run sees depends on the day.
	if _, hosting := raw["is_hosting"]; hosting == expired {
		t.Errorf("is_hosting served: %v, trial_expired: %v; one must be the other's opposite", hosting, expired)
	}
}

func TestAFreePlanKeysBatchOfTwoIsRefusedAsABadRequestOnce(t *testing.T) {
	if reason := trialRung().skipReason(); reason != "" {
		t.Skip(reason)
	}
	client, rec := clientFor(t, trialRung())

	got, err := client.LookupBatch(t.Context(), []string{probe, "8.8.8.8"})
	if err != nil {
		t.Fatalf("LookupBatch: %v", err)
	}

	for _, ip := range []string{probe, "8.8.8.8"} {
		var refused *vpndetection.Error
		if !errors.As(got[ip].Err, &refused) {
			t.Fatalf("%s: a free-plan key's batch of two answered %+v, want a refusal", ip, got[ip])
		}
		if refused.Kind != vpndetection.KindBadRequest || refused.StatusCode != http.StatusPaymentRequired {
			t.Errorf("%s: refused as %s %d, want bad_request 402", ip, refused.Kind, refused.StatusCode)
		}
	}
	var paths []string
	for _, f := range rec.seen() {
		paths = append(paths, f.path)
	}
	if !slices.Equal(paths, []string{"/batch"}) {
		t.Errorf("the batch asked for %v, want one /batch, never retried", paths)
	}
}

func TestAFreePlanKeysBatchOfOneIsAnswered(t *testing.T) {
	if reason := trialRung().skipReason(); reason != "" {
		t.Skip(reason)
	}
	client, rec := clientFor(t, trialRung())

	got, err := client.LookupBatch(t.Context(), []string{probe})
	if err != nil {
		t.Fatalf("LookupBatch: %v", err)
	}

	if got[probe].Err != nil {
		t.Fatalf("a free-plan key's batch of one failed: %v", got[probe].Err)
	}
	results, _ := rec.jsonBody(t, "/batch")["results"].(map[string]any)
	answer, _ := results[probe].(map[string]any)
	if _, ok := answer["trial_expired"].(bool); !ok {
		t.Errorf("the answer carries trial_expired %v, want a boolean", answer["trial_expired"])
	}
}

func TestAFieldAHigherTierServesIsAbsentOnALowerOneNeverFalse(t *testing.T) {
	if reason := ladderSkip(); reason != "" {
		t.Skip(reason)
	}

	open := observableRungs()
	fixtures := make([]*fixture, len(open))
	for i, r := range open {
		fixtures[i] = answerFor(t, r)
	}

	// The positive half: a field the wire carried must have reached the result,
	// which is what makes a served `false` survive. A field the client does not
	// model at all is the API moving ahead of the pinned spec, not a drop.
	for _, f := range fixtures {
		for _, field := range slices.Sorted(maps.Keys(f.raw)) {
			value, served := servedField(t, f.result, field)
			if value.IsValid() && !served {
				t.Errorf("%s serves %s and the client dropped it", f.rung.tier, field)
			}
		}
	}

	for i, lower := range fixtures {
		higher := map[string]bool{}
		for _, f := range fixtures[i+1:] {
			for field := range f.raw {
				higher[field] = true
			}
		}
		for _, field := range slices.Sorted(maps.Keys(higher)) {
			if _, onTheWire := lower.raw[field]; onTheWire {
				continue
			}
			value, served := servedField(t, lower.result, field)
			if !value.IsValid() || !served {
				continue
			}
			t.Errorf("%s is not in the %s plan, so the result must not read as %v",
				field, lower.rung.tier, value.Interface())
		}
	}
}

func TestABogonIsAnsweredWithoutTouchingTheNetwork(t *testing.T) {
	client, err := vpndetection.New(
		vpndetection.WithBaseURL(staging),
		vpndetection.WithHTTPClient(&http.Client{Transport: refusing{}}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	r, err := client.Lookup(t.Context(), "10.0.0.1")
	if err != nil {
		t.Fatalf("Lookup(10.0.0.1): %v", err)
	}

	if !r.IsBogon {
		t.Error("a private address must be answered locally")
	}
	if r.IsVpn {
		t.Error("a private address cannot be VPN infrastructure")
	}
	if !vpndetection.IsBogon("10.0.0.1") {
		t.Error("the standalone function must agree with the client")
	}
	// Computed rather than served, so it carries every field whatever the plan.
	for name := range members {
		flag, served := servedField(t, r, "is_"+name)
		if !served || boolOf(flag) {
			t.Errorf("is_%s must be present and false on a bogon", name)
		}
		object, served := servedField(t, r, name)
		if !served {
			t.Errorf("%s must be present and empty on a bogon", name)
			continue
		}
		empty := reflect.New(object.Type().Elem()).Elem().Interface()
		if !reflect.DeepEqual(object.Elem().Interface(), empty) {
			t.Errorf("%s must be present and EMPTY on a bogon, got %+v", name, object.Elem().Interface())
		}
	}
}

func TestABatchWithoutAKeyIsRefusedOnceAndItsBogonStillAnswered(t *testing.T) {
	client, rec := clientFor(t, unauthRung())

	// Two addresses on the wire: a keyless batch of one is answered as its lookup.
	got, err := client.LookupBatch(t.Context(), []string{probe, "8.8.8.8", "10.0.0.1"})
	if err != nil {
		t.Fatalf("LookupBatch: %v", err)
	}

	if bogon := got["10.0.0.1"]; bogon.Err != nil || !bogon.Result.IsBogon {
		t.Errorf("10.0.0.1 was not answered locally: %+v", bogon)
	}
	var refused *vpndetection.Error
	if !errors.As(got[probe].Err, &refused) {
		t.Fatalf("a batch without a key answered %+v, want an unauthorized error", got[probe])
	}
	if refused.Kind != vpndetection.KindUnauthorized || refused.StatusCode != http.StatusUnauthorized {
		t.Errorf("a batch without a key failed as %s %d, want unauthorized 401", refused.Kind, refused.StatusCode)
	}
	if refused.Retryable() {
		t.Error("a batch without a key must not be retryable")
	}
	var paths []string
	for _, f := range rec.seen() {
		paths = append(paths, f.path)
	}
	if !slices.Equal(paths, []string{"/batch"}) {
		t.Errorf("the batch asked for %v, want one /batch, never retried", paths)
	}
}

func TestABatchCollapsesDuplicatesAndKeepsBogonsOffTheWire(t *testing.T) {
	// A batch needs a paid plan, and starter is the cheapest.
	if reason := paidRung().skipReason(); reason != "" {
		t.Skip(reason)
	}
	client, rec := clientFor(t, paidRung())

	got, err := client.LookupBatch(t.Context(),
		[]string{probe, "8.8.8.8", probe, "10.0.0.1", "8.8.8.8"})
	if err != nil {
		t.Fatalf("LookupBatch: %v", err)
	}

	if len(got) != 3 {
		t.Errorf("the batch answered %d address(es), want 3: %v", len(got), slices.Sorted(maps.Keys(got)))
	}
	// Distinct paths rather than a call count, so a retry against a wobbling
	// staging cannot read as a failure to deduplicate.
	asked := map[string]bool{}
	for _, f := range rec.seen() {
		asked[f.path] = true
		if !f.carriedKey {
			t.Errorf("a request to %s went without the paid key", f.path)
		}
	}
	if paths := slices.Sorted(maps.Keys(asked)); !slices.Equal(paths, []string{"/batch"}) {
		t.Errorf("the batch asked for %v, want only /batch", paths)
	}
	// The server answers exactly the addresses it was sent, once each.
	answer := rec.jsonBody(t, "/batch")
	var sent []string
	for _, member := range []string{"results", "errors"} {
		entries, _ := answer[member].(map[string]any)
		sent = append(sent, slices.Collect(maps.Keys(entries))...)
	}
	want := []string{probe, "8.8.8.8"}
	slices.Sort(sent)
	slices.Sort(want)
	if !slices.Equal(sent, want) {
		t.Errorf("the batch sent %v, want %v", sent, want)
	}
	if bogon := got["10.0.0.1"]; bogon.Err != nil || !bogon.Result.IsBogon {
		t.Errorf("10.0.0.1 was not answered locally: %+v", bogon)
	}
	for _, ip := range []string{probe, "8.8.8.8"} {
		if got[ip].Err != nil {
			t.Errorf("%s failed: %v", ip, got[ip].Err)
		}
	}
}

type refusing struct{}

func (refusing) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("the bogon path reached the network")
}
