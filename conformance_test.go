// Asserts the shared conformance corpus that every VPNDetection SDK asserts.
//
// The corpus is generated into testdata/ and is identical across languages, so
// a behavior that drifts here fails here rather than surfacing as two client
// libraries quietly disagreeing about the same address.

package vpndetection

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestIsBogonMatchesTheCanonicalRanges(t *testing.T) {
	for _, c := range corpus(t).IsBogon {
		if got := IsBogon(c.IP); got != c.Expect {
			t.Errorf("IsBogon(%q) = %v, want %v (%s)", c.IP, got, c.Expect, c.Why)
		}
	}
}

func TestBogonIsAnsweredLocallyInTheFullMaxShape(t *testing.T) {
	data := corpus(t)
	stub := newStub(nil)
	client := newTestClient(t, stub)

	result, err := client.Lookup(t.Context(), "10.0.0.1")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	if !result.IsBogon {
		t.Error("IsBogon should mark a locally computed answer")
	}
	if result.IP != "10.0.0.1" {
		t.Errorf("IP = %q, want 10.0.0.1", result.IP)
	}
	for _, name := range data.BogonResponse.FlagsFalse {
		assertFlag(t, result, name, false)
	}
	for _, name := range data.BogonResponse.EmptyObjects {
		assertEmptyObject(t, result, name)
	}
	if stub.count() != 0 {
		t.Errorf("a bogon must not reach the network, got %d request(s)", stub.count())
	}
}

func TestLookupPreservesAbsentVersusFalseAcrossEveryPlanShape(t *testing.T) {
	for _, c := range corpus(t).Lookup {
		t.Run(c.Name, func(t *testing.T) {
			var wire struct {
				IP string `json:"ip"`
			}
			if err := json.Unmarshal(c.Body, &wire); err != nil {
				t.Fatalf("fixture body: %v", err)
			}
			stub := newStub(map[string]stubRoute{
				wire.IP: {status: c.Status, body: json.RawMessage(c.Body)},
			})
			client := newTestClient(t, stub)

			result, err := client.Lookup(t.Context(), wire.IP)
			if err != nil {
				t.Fatalf("Lookup: %v", err)
			}

			if result.IP != c.Expect.IP {
				t.Errorf("IP = %q, want %q", result.IP, c.Expect.IP)
			}
			if result.IsBogon != c.Expect.IsBogon {
				t.Errorf("IsBogon = %v, want %v", result.IsBogon, c.Expect.IsBogon)
			}
			for name, want := range c.Expect.Present {
				assertFlag(t, result, name, want)
			}
			for _, name := range c.Expect.Absent {
				assertAbsent(t, result, name)
			}
			for _, name := range c.Expect.EmptyPresent {
				assertEmptyObject(t, result, name)
			}
			assertObject(t, result, "vpn", c.Expect.Vpn)
			assertObject(t, result, "hosting", c.Expect.Hosting)
			assertObject(t, result, "dcproxy", c.Expect.Dcproxy)
		})
	}
}

func TestA429IsClassifiedByRetryAfterNotByItsStatus(t *testing.T) {
	for _, c := range corpus(t).Errors {
		t.Run(c.Name, func(t *testing.T) {
			stub := newStub(map[string]stubRoute{
				"1.1.1.1": {status: c.Status, body: json.RawMessage(c.Body), headers: c.Headers},
			})
			// No retries, so a retryable failure surfaces rather than looping.
			client := newTestClient(t, stub, WithRetries(0))

			_, err := client.Lookup(t.Context(), "1.1.1.1")
			var apiErr *Error
			if !errors.As(err, &apiErr) {
				t.Fatalf("error was %v, want a *vpndetection.Error", err)
			}
			if string(apiErr.Kind) != c.Expect.Kind {
				t.Errorf("Kind = %q, want %q", apiErr.Kind, c.Expect.Kind)
			}
			if apiErr.Retryable() != c.Expect.Retryable {
				t.Errorf("Retryable() = %v, want %v", apiErr.Retryable(), c.Expect.Retryable)
			}
			if c.Expect.Message != "" && apiErr.Message != c.Expect.Message {
				t.Errorf("Message = %q, want %q", apiErr.Message, c.Expect.Message)
			}
			if c.Expect.RetryAfterSeconds != nil {
				want := *c.Expect.RetryAfterSeconds
				if got := int(apiErr.RetryAfter.Seconds()); got != want {
					t.Errorf("RetryAfter = %ds, want %ds", got, want)
				}
			}
		})
	}
}

func TestBatchDedupesShortCircuitsBogonsAndKeysByAddress(t *testing.T) {
	c := batchCase(t, "dedup-bogon-and-order-free-keying")
	stub := newStub(okRoutes("1.1.1.1", "8.8.8.8"))
	client := newTestClient(t, stub)

	got, err := client.LookupBatch(t.Context(), c.Input)
	if err != nil {
		t.Fatalf("LookupBatch: %v", err)
	}

	// Keyed by address, not positional. A Go map has no order of its own, so
	// the corpus's key list is asserted as a set.
	assertKeys(t, got, c.Expect.Keys)
	if stub.count() != *c.Expect.HTTPRequests {
		t.Errorf("issued %d request(s), want %d", stub.count(), *c.Expect.HTTPRequests)
	}
	for _, ip := range c.Expect.BogonKeys {
		if !got[ip].Result.IsBogon {
			t.Errorf("%s should be a local answer", ip)
		}
	}
}

func TestOneBadAddressDoesNotLoseTheRestOfTheBatch(t *testing.T) {
	c := batchCase(t, "partial-failure-does-not-fail-the-batch")
	stub := newStub(okRoutes("1.1.1.1"))
	client := newTestClient(t, stub, WithRetries(0))

	got, err := client.LookupBatch(t.Context(), c.Input)
	if err != nil {
		t.Fatalf("LookupBatch: %v", err)
	}

	assertKeys(t, got, c.Expect.Keys)
	for _, ip := range c.Expect.ErrorKeys {
		var apiErr *Error
		if !errors.As(got[ip].Err, &apiErr) {
			t.Errorf("%s should carry its own error, got %v", ip, got[ip].Err)
		}
	}
	if good := got["1.1.1.1"]; good.Err != nil || good.Result.IsVpn {
		t.Errorf("the good address should still have answered, got %+v", good)
	}
}

func TestACacheHitIssuesNoSecondRequest(t *testing.T) {
	c := batchCase(t, "cache-hit-issues-no-second-request")
	stub := newStub(okRoutes("1.1.1.1"))
	client := newTestClient(t, stub)

	for range c.Repeat {
		if _, err := client.LookupBatch(t.Context(), c.Input); err != nil {
			t.Fatalf("LookupBatch: %v", err)
		}
	}
	if stub.count() != *c.Expect.HTTPRequests {
		t.Errorf("issued %d request(s), want %d", stub.count(), *c.Expect.HTTPRequests)
	}
}

func TestTwoClientsNeverShareACachedAnswer(t *testing.T) {
	stub := newStub(okRoutes("1.1.1.1"))
	a := newTestClient(t, stub, WithAPIKey("key-a"))
	b := newTestClient(t, stub, WithAPIKey("key-b"))

	if _, err := a.Lookup(t.Context(), "1.1.1.1"); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if _, err := b.Lookup(t.Context(), "1.1.1.1"); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	// Two keys can be on different plans and so entitled to different fields; a
	// shared cache would serve one of them the other's shape.
	if stub.count() != 2 {
		t.Errorf("issued %d request(s), want 2", stub.count())
	}
}

func TestCachingCanBeTurnedOff(t *testing.T) {
	stub := newStub(okRoutes("1.1.1.1"))
	client := newTestClient(t, stub, WithoutCache())

	for range 2 {
		if _, err := client.Lookup(t.Context(), "1.1.1.1"); err != nil {
			t.Fatalf("Lookup: %v", err)
		}
	}
	if stub.count() != 2 {
		t.Errorf("issued %d request(s), want 2", stub.count())
	}
}

// The compiled-in table and the corpus are emitted by the same generator run,
// so a mismatch means one of the two was regenerated without the other.
func TestBogonTableMatchesTheCorpus(t *testing.T) {
	data := corpus(t)
	if !slices.Equal(bogonV4, data.Bogons.V4) {
		t.Errorf("bogonV4 differs from the corpus:\n got %v\nwant %v", bogonV4, data.Bogons.V4)
	}
	if !slices.Equal(bogonV6, data.Bogons.V6) {
		t.Errorf("bogonV6 differs from the corpus:\n got %v\nwant %v", bogonV6, data.Bogons.V6)
	}
}

// Guards the panic in parsePrefixes: it can only ever fire on a broken build.
func TestBogonTableParses(t *testing.T) {
	for _, cidr := range slices.Concat(bogonV4, bogonV6) {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			t.Errorf("bogon range %q does not parse: %v", cidr, err)
		}
	}
	if len(bogonPrefixesV4()) != len(bogonV4) || len(bogonPrefixesV6()) != len(bogonV6) {
		t.Error("the parsed tables do not cover every generated range")
	}
}

func newTestClient(t *testing.T, stub *stubTransport, opts ...Option) *Client {
	t.Helper()
	client, err := New(append([]Option{WithHTTPClient(stub.client())}, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

func assertFlag(t *testing.T, result *Result, wire string, want bool) {
	t.Helper()
	field := wireField(t, result, wire)
	if field.Kind() != reflect.Ptr {
		if field.Bool() != want {
			t.Errorf("%s = %v, want %v", wire, field.Bool(), want)
		}
		return
	}
	if field.IsNil() {
		t.Errorf("%s must be present and %v, but is absent", wire, want)
		return
	}
	if got := field.Elem().Bool(); got != want {
		t.Errorf("%s = %v, want %v", wire, got, want)
	}
}

func assertAbsent(t *testing.T, result *Result, wire string) {
	t.Helper()
	field := wireField(t, result, wire)
	if field.Kind() != reflect.Ptr {
		t.Errorf("%s is not optional, so it cannot express absent-versus-false", wire)
		return
	}
	if !field.IsNil() {
		t.Errorf("%s must be ABSENT, not %v", wire, field.Elem().Interface())
	}
}

func assertEmptyObject(t *testing.T, result *Result, wire string) {
	t.Helper()
	field := wireField(t, result, wire)
	if field.IsNil() {
		t.Errorf("%s must be present and empty, but is absent", wire)
		return
	}
	empty := reflect.New(field.Type().Elem()).Elem().Interface()
	if !reflect.DeepEqual(field.Elem().Interface(), empty) {
		t.Errorf("%s must be present and EMPTY, got %+v", wire, field.Elem().Interface())
	}
}

func assertObject(t *testing.T, result *Result, wire string, want json.RawMessage) {
	t.Helper()
	if len(want) == 0 {
		return
	}
	got, err := json.Marshal(wireField(t, result, wire).Interface())
	if err != nil {
		t.Fatalf("%s: %v", wire, err)
	}
	var gotAny, wantAny any
	if err := json.Unmarshal(got, &gotAny); err != nil {
		t.Fatalf("%s: %v", wire, err)
	}
	if err := json.Unmarshal(want, &wantAny); err != nil {
		t.Fatalf("%s fixture: %v", wire, err)
	}
	if !reflect.DeepEqual(gotAny, wantAny) {
		t.Errorf("%s = %s, want %s", wire, got, want)
	}
}

func assertKeys(t *testing.T, got map[string]BatchResult, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("batch has %d key(s), want %d: %v", len(got), len(want), got)
	}
	for _, ip := range want {
		if _, ok := got[ip]; !ok {
			t.Errorf("batch is missing the key %q", ip)
		}
	}
}

// Looks a field up by its WIRE name, so the corpus asserts the names the API
// actually serves rather than whatever the generator called them.
func wireField(t *testing.T, result *Result, wire string) reflect.Value {
	t.Helper()
	value := reflect.ValueOf(result.LookupResponse)
	for i := range value.NumField() {
		tag, _, _ := strings.Cut(value.Type().Field(i).Tag.Get("json"), ",")
		if tag == wire {
			return value.Field(i)
		}
	}
	t.Fatalf("LookupResponse has no field tagged %q", wire)
	return reflect.Value{}
}

func batchCase(t *testing.T, name string) corpusBatch {
	t.Helper()
	for _, c := range corpus(t).Batch {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("the corpus has no batch case named %q", name)
	return corpusBatch{}
}

func corpus(t *testing.T) corpusData {
	t.Helper()
	raw, err := os.ReadFile("testdata/testdata.json")
	if err != nil {
		t.Fatalf("reading the corpus: %v", err)
	}
	var data corpusData
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatalf("parsing the corpus: %v", err)
	}
	return data
}

type corpusData struct {
	IsBogon []struct {
		IP     string `json:"ip"`
		Expect bool   `json:"expect"`
		Why    string `json:"why"`
	} `json:"isBogon"`
	BogonResponse struct {
		FlagsFalse   []string `json:"flagsFalse"`
		EmptyObjects []string `json:"emptyObjects"`
	} `json:"bogonResponse"`
	Lookup []struct {
		Name   string          `json:"name"`
		Status int             `json:"status"`
		Body   json.RawMessage `json:"body"`
		Expect struct {
			IP           string          `json:"ip"`
			IsBogon      bool            `json:"isBogon"`
			Present      map[string]bool `json:"present"`
			Absent       []string        `json:"absent"`
			EmptyPresent []string        `json:"emptyPresent"`
			Vpn          json.RawMessage `json:"vpn"`
			Hosting      json.RawMessage `json:"hosting"`
			Dcproxy      json.RawMessage `json:"dcproxy"`
		} `json:"expect"`
	} `json:"lookup"`
	Errors []struct {
		Name    string            `json:"name"`
		Status  int               `json:"status"`
		Headers map[string]string `json:"headers"`
		Body    json.RawMessage   `json:"body"`
		Expect  struct {
			Kind              string `json:"kind"`
			Retryable         bool   `json:"retryable"`
			Message           string `json:"message"`
			RetryAfterSeconds *int   `json:"retryAfterSeconds"`
		} `json:"expect"`
	} `json:"errors"`
	Batch  []corpusBatch `json:"batch"`
	Bogons struct {
		V4 []string `json:"v4"`
		V6 []string `json:"v6"`
	} `json:"bogons"`
}

type corpusBatch struct {
	Name   string   `json:"name"`
	Input  []string `json:"input"`
	Repeat int      `json:"repeat"`
	Expect struct {
		Keys         []string `json:"keys"`
		HTTPRequests *int     `json:"httpRequests"`
		BogonKeys    []string `json:"bogonKeys"`
		ErrorKeys    []string `json:"errorKeys"`
	} `json:"expect"`
}
