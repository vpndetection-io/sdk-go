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

	vpndetection "github.com/vpndetection-io/sdk-go/v3"
)

func TestAnUnauthenticatedLookupAnswersIPAndIsVpn(t *testing.T) {
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
		t.Logf("%s: %d fields", r.tier, len(f.raw))
		if below == nil {
			below = f
			continue
		}
		for field := range below.raw {
			if _, ok := f.raw[field]; !ok {
				t.Errorf("%s drops %s, which %s serves", r.tier, field, below.rung.tier)
			}
		}
		// Without this a run in which every key resolved to the same plan would
		// pass: identical sets satisfy containment in both directions.
		if r.widens && len(f.raw) <= len(below.raw) {
			t.Errorf("%s answers %d field(s) and %s answers %d, so it is no wider",
				r.tier, len(f.raw), below.rung.tier, len(below.raw))
		}
		below = f
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

func TestABatchCollapsesDuplicatesAndKeepsBogonsOffTheWire(t *testing.T) {
	client, rec := clientFor(t, unauthRung())

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
	}
	want := []string{"/" + probe, "/8.8.8.8"}
	if paths := slices.Sorted(maps.Keys(asked)); !slices.Equal(paths, want) {
		t.Errorf("the batch asked for %v, want %v", paths, want)
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
