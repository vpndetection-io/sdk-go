// The staging fixtures the test files share: one client per tier, one lookup per
// tier, and the shape rules that hold whatever the plan.

package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	vpndetection "github.com/vpndetection-io/sdk-go"
)

const (
	staging = "https://api-staging.vpndetection.io"
	// A stable VPN address, and the one the README teaches.
	probe = "45.83.91.1"
	// Bodies above this are never held: a dataset transfer runs through the same
	// transport as a lookup.
	maxCapturedBody = 1 << 20
)

// One entry per dataset the API answers about. required is what a POPULATED
// detail object carries on every tier; optional is the max-only remainder, which
// is absent rather than empty on a lower plan.
var members = map[string]detail{
	"vpn":      {required: []string{"provider", "last_seen"}, optional: []string{"confidence", "method"}},
	"hosting":  {required: classKeys},
	"relay":    {required: classKeys},
	"tor":      {required: classKeys},
	"cdn":      {required: classKeys},
	"resproxy": {required: proxyKeys},
	"dcproxy":  {required: proxyKeys},
	"mobproxy": {required: proxyKeys},
}

var (
	classKeys = []string{"provider", "confidence", "last_seen"}
	proxyKeys = []string{"provider", "first_seen", "last_seen", "hits", "hits_days_pct", "providers_num"}
)

type detail struct {
	required []string
	optional []string
}

// What a test is allowed to remember about a request it made.
//
// Only derived facts leave here. An assertion that fails prints its operands, so
// holding on to the request itself is how a key ends up in a public CI log:
// whether the key was carried is a boolean, and the caller never sees the key.
type fact struct {
	origin     string
	path       string
	carriedKey bool
}

type fixture struct {
	rung       rung
	result     *vpndetection.Result
	raw        map[string]any
	carriedKey bool
}

func clientFor(t *testing.T, r rung) (*vpndetection.Client, *recorder) {
	t.Helper()
	rec := &recorder{key: r.key(), bodies: map[string]json.RawMessage{}}
	opts := []vpndetection.Option{
		vpndetection.WithBaseURL(staging),
		vpndetection.WithHTTPClient(&http.Client{Transport: rec}),
	}
	if rec.key != "" {
		opts = append(opts, vpndetection.WithAPIKey(rec.key))
	}
	client, err := vpndetection.New(opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client, rec
}

// One lookup per tier for the whole run. The client caches, so a second reader
// of the same tier would cost no request either, but the fixture also carries
// what the wire said, which the client does not keep.
var (
	answersMu sync.Mutex
	answers   = map[string]*fixture{}
)

func answerFor(t *testing.T, r rung) *fixture {
	t.Helper()
	answersMu.Lock()
	defer answersMu.Unlock()
	if got, ok := answers[r.tier]; ok {
		return got
	}

	client, rec := clientFor(t, r)
	result, err := client.Lookup(t.Context(), probe)
	if err != nil {
		t.Fatalf("%s: Lookup(%s): %v", r.tier, probe, err)
	}
	got := &fixture{
		rung:       r,
		result:     result,
		raw:        rec.jsonBody(t, "/"+probe),
		carriedKey: rec.carriedKey(),
	}
	// Checked here rather than in one test, so no comparison anywhere can be made
	// against a tier that silently ran unauthenticated: an empty or unsent key
	// answers the free shape, which satisfies every containment check vacuously.
	if r.secret != "" && !got.carriedKey {
		t.Fatalf("%s: the key never reached the wire", r.tier)
	}
	answers[r.tier] = got
	return got
}

func assertServedByTier(t *testing.T, f *fixture) {
	t.Helper()
	if f.result.IP != probe {
		t.Errorf("%s: answered about %q, want %q", f.rung.tier, f.result.IP, probe)
	}
	if f.result.IsBogon {
		t.Errorf("%s: a served answer is not a local one", f.rung.tier)
	}
	assertShape(t, f.rung.tier, f.result, f.raw)
}

// Holds on every plan: presence is the plan, the value is the answer.
func assertShape(t *testing.T, tier string, r *vpndetection.Result, raw map[string]any) {
	t.Helper()
	if _, ok := raw["ip"].(string); !ok {
		t.Errorf("%s: ip is %v, want a string", tier, raw["ip"])
	}
	served, ok := raw["is_vpn"].(bool)
	if !ok {
		t.Fatalf("%s: is_vpn is %v, and it is on every plan", tier, raw["is_vpn"])
	}
	if r.IsVpn != served {
		t.Errorf("%s: is_vpn was %v on the wire and %v on the result", tier, served, r.IsVpn)
	}

	for name, spec := range members {
		flag := "is_" + name
		if value, present := raw[flag]; present {
			if _, ok := value.(bool); !ok {
				t.Errorf("%s: %s is present, so it must be a real boolean, not %v", tier, flag, value)
			}
		}
		object, present := raw[name]
		if !present {
			continue
		}
		// A detail object without its flag would leave a caller reading the object
		// to find out whether the address is flagged at all.
		if _, ok := raw[flag]; !ok {
			t.Errorf("%s: %s is served without %s", tier, name, flag)
		}
		assertDetail(t, tier, name, spec, object, raw[flag])
	}
}

func assertDetail(t *testing.T, tier, name string, spec detail, object, flag any) {
	t.Helper()
	fields, ok := object.(map[string]any)
	if !ok {
		t.Errorf("%s: %s must be an object when present, got %v", tier, name, object)
		return
	}
	if len(fields) == 0 {
		if flag != false {
			t.Errorf("%s: %s is empty, so is_%s must be false, not %v", tier, name, name, flag)
		}
		return
	}
	for _, key := range spec.required {
		if _, ok := fields[key]; !ok {
			t.Errorf("%s: %s is populated but carries no %s", tier, name, key)
		}
	}
	for key := range fields {
		if !slices.Contains(spec.required, key) && !slices.Contains(spec.optional, key) {
			t.Errorf("%s: %s.%s is not a documented key of this detail object", tier, name, key)
		}
	}
}

// Looks a member up by its WIRE name, so a test says "this field is absent"
// about the name the API serves rather than whatever the generator called it.
// Reports whether the client holds a value for it at all.
func servedField(t *testing.T, r *vpndetection.Result, wire string) (reflect.Value, bool) {
	t.Helper()
	value := reflect.ValueOf(r.LookupResponse)
	for i := range value.NumField() {
		tag, _, _ := strings.Cut(value.Type().Field(i).Tag.Get("json"), ",")
		if tag != wire {
			continue
		}
		field := value.Field(i)
		if field.Kind() == reflect.Ptr {
			return field, !field.IsNil()
		}
		return field, true
	}
	return reflect.Value{}, false
}

// Reads a flag whether or not the plan made it optional: is_vpn is on every
// plan and so is a plain bool, while the other seven are pointers.
func boolOf(flag reflect.Value) bool {
	if flag.Kind() == reflect.Ptr {
		return flag.Elem().Bool()
	}
	return flag.Bool()
}

// Records what was asked for and holds on to small JSON answers: the client
// keeps the decoded result, and these tests also need what the wire carried.
type recorder struct {
	key string

	mu     sync.Mutex
	facts  []fact
	bodies map[string]json.RawMessage
}

func (rec *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	rec.note(req)
	res, err := http.DefaultTransport.RoundTrip(req)
	if err != nil || res == nil {
		return res, err
	}
	return rec.capture(req, res)
}

func (rec *recorder) note(req *http.Request) {
	carried := rec.key != "" && strings.Contains(req.URL.String(), rec.key)
	for _, values := range req.Header {
		for _, value := range values {
			carried = carried || (rec.key != "" && strings.Contains(value, rec.key))
		}
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.facts = append(rec.facts, fact{
		origin: originOf(req.URL), path: req.URL.Path, carriedKey: carried,
	})
}

// Only a small JSON answer is held, and only ever the first megabyte of one. A
// dataset transfer runs through this same transport, so reading a body to its
// end here would be the multi-gigabyte mistake the SDK exists to avoid. The
// bytes read are handed back in front of the rest, so the client still sees the
// whole body whatever the outcome.
func (rec *recorder) capture(req *http.Request, res *http.Response) (*http.Response, error) {
	if !strings.HasPrefix(res.Header.Get("Content-Type"), "application/json") {
		return res, nil
	}
	head, err := io.ReadAll(io.LimitReader(res.Body, maxCapturedBody+1))
	if err != nil {
		res.Body.Close()
		return nil, err
	}
	rest := res.Body
	res.Body = readCloser{Reader: io.MultiReader(bytes.NewReader(head), rest), Closer: rest}
	if len(head) > maxCapturedBody {
		return res, nil
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.bodies[req.URL.Path] = head
	return res, nil
}

type readCloser struct {
	io.Reader
	io.Closer
}

func (rec *recorder) jsonBody(t *testing.T, path string) map[string]any {
	t.Helper()
	rec.mu.Lock()
	raw, ok := rec.bodies[path]
	rec.mu.Unlock()
	if !ok {
		t.Fatalf("no JSON answer was captured for %s", path)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("parsing the answer to %s: %v", path, err)
	}
	return body
}

func (rec *recorder) carriedKey() bool {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	for _, f := range rec.facts {
		if f.carriedKey {
			return true
		}
	}
	return false
}

func (rec *recorder) seen() []fact {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return slices.Clone(rec.facts)
}

func originOf(u *url.URL) string {
	return u.Scheme + "://" + u.Host
}
