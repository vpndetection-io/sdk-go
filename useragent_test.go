package vpndetection

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"runtime/debug"
	"sync"
	"testing"
	"time"
)

// What a transport passed to WithHTTPClient sees, which is where a wrapping
// program puts its own name first.
type agentRecorder struct {
	next   http.RoundTripper
	mu     sync.Mutex
	agents map[string]string
}

func (r *agentRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.agents[req.Method+" "+req.URL.Path] = req.Header.Get("User-Agent")
	r.mu.Unlock()
	return r.next.RoundTrip(req)
}

// Its own tests are built from the working tree, which Go records as (devel).
const testAgent = "vpndetection-go/devel"

func TestEveryAPIRequestNamesTheSDK(t *testing.T) {
	stub := newStub(map[string]stubRoute{
		"8.8.8.8": {body: map[string]any{"ip": "8.8.8.8", "is_vpn": false}},
		"1.1.1.1": {body: map[string]any{"ip": "1.1.1.1", "is_vpn": false}},
		"9.9.9.9": {body: map[string]any{"ip": "9.9.9.9", "is_vpn": false}},
		"myip":    {body: map[string]any{"ip": "203.0.113.9", "is_vpn": false}},
	})
	recorder := &agentRecorder{next: stub, agents: map[string]string{}}
	client, err := New(WithHTTPClient(&http.Client{Transport: recorder}), WithAPIKey(testKey))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := client.Lookup(t.Context(), "8.8.8.8"); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if _, err := client.LookupBatch(t.Context(), []string{"1.1.1.1", "9.9.9.9"}); err != nil {
		t.Fatalf("LookupBatch: %v", err)
	}
	if _, err := client.MyIP(t.Context()); err != nil {
		t.Fatalf("MyIP: %v", err)
	}
	// Timed: a per-call timeout sends on a copy of the client.
	if _, err := client.Lookup(t.Context(), "8.8.8.8", Timeout(time.Second)); err != nil {
		t.Fatalf("Lookup with a timeout: %v", err)
	}

	for _, request := range []string{"GET /8.8.8.8", "POST /batch", "GET /myip"} {
		agent, ok := recorder.agents[request]
		if !ok {
			t.Errorf("%s was never sent", request)
		} else if agent != testAgent {
			t.Errorf("%s carried User-Agent %q, want %q", request, agent, testAgent)
		}
	}
}

func TestOauthRequestsNameTheSDK(t *testing.T) {
	stub := &oauthStub{replies: []oauthReply{{Status: 200, Body: json.RawMessage(everyRequiredMember)}}}
	client := newOauthClient(t, stub)
	client.Oauth.sleep = func(context.Context, time.Duration) error { return nil }

	if _, err := client.Oauth.Metadata(t.Context()); err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if err := client.Oauth.Revoke(t.Context(), "vpndetection-cli", "mo_rt_x"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if len(stub.requests) != 2 {
		t.Fatalf("saw %d request(s), want 2", len(stub.requests))
	}
	for _, req := range stub.requests {
		if agent := req.header.Get("User-Agent"); agent != testAgent {
			t.Errorf("%s %s carried User-Agent %q, want %q", req.method, req.path, agent, testAgent)
		}
	}
}

// Object storage's request is a second one, sent past the generated client.
func TestTheDownloadNamesTheSDKToTheAPIAndToObjectStorage(t *testing.T) {
	origin := newOrigin(t, originConfig{})

	path := filepath.Join(t.TempDir(), "keys.csv.gz")
	if _, err := origin.client.Database.DownloadFile(t.Context(), "cdn_ip_v1", FormatCSVGZ, path); err != nil {
		t.Fatalf("DownloadFile: %v", err)
	}
	for _, at := range []string{"/api/v1/database/download", "/blob"} {
		if agent := origin.request(t, at).Header.Get("User-Agent"); agent != testAgent {
			t.Errorf("%s carried User-Agent %q, want %q", at, agent, testAgent)
		}
	}
}

func TestTheVersionIsTheOneTheProgramWasBuiltWith(t *testing.T) {
	other := debug.Module{Path: "example.com/app", Version: "(devel)"}
	cases := []struct {
		name string
		info *debug.BuildInfo
		ok   bool
		want string
	}{
		{"a dependency at a tag", &debug.BuildInfo{Main: other, Deps: []*debug.Module{
			{Path: "golang.org/x/sync", Version: "v0.23.0"},
			{Path: modulePath, Version: "v5.14.0"},
		}}, true, "vpndetection-go/5.14.0"},
		{"a pseudo-version", &debug.BuildInfo{Main: other, Deps: []*debug.Module{
			{Path: modulePath, Version: "v5.14.1-0.20261113070000-0123456789ab"},
		}}, true, "vpndetection-go/5.14.1-0.20261113070000-0123456789ab"},
		{"replaced by a fork's tag", &debug.BuildInfo{Main: other, Deps: []*debug.Module{
			{Path: modulePath, Version: "v5.14.0", Replace: &debug.Module{Path: "example.com/fork/v5", Version: "v5.14.2"}},
		}}, true, "vpndetection-go/5.14.2"},
		{"replaced by a local directory", &debug.BuildInfo{Main: other, Deps: []*debug.Module{
			{Path: modulePath, Version: "v5.14.0", Replace: &debug.Module{Path: "../sdk-go"}},
		}}, true, testAgent},
		{"its own module", &debug.BuildInfo{Main: debug.Module{Path: modulePath, Version: "(devel)"}}, true, testAgent},
		{"another program not naming it", &debug.BuildInfo{Main: other}, true, testAgent},
		{"no build information", nil, false, testAgent},
	}
	for _, c := range cases {
		if got := agentFrom(c.info, c.ok); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
