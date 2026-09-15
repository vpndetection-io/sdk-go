package vpndetection

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// An HTTP transport that answers lookups from a table and records what it was
// asked for, so "never touched the network" and "kept at most N in flight" are
// asserted rather than assumed.
type stubTransport struct {
	routes   map[string]stubRoute
	delay    time.Duration
	mu       sync.Mutex
	calls    []string
	inFlight int
	peak     int
}

type stubRoute struct {
	status  int
	body    any
	headers map[string]string
}

func newStub(routes map[string]stubRoute) *stubTransport {
	return &stubTransport{routes: routes}
}

func (s *stubTransport) client() *http.Client {
	return &http.Client{Transport: s}
}

func (s *stubTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	s.enter(req.URL.String())
	defer s.leave()
	if s.delay > 0 {
		time.Sleep(s.delay)
	}

	if req.Method == http.MethodPost && req.URL.Path == "/batch" {
		return s.respond(req, s.batch(req)), nil
	}
	route, ok := s.routes[stubKey(req)]
	if !ok {
		route = stubRoute{
			status: http.StatusBadRequest,
			body:   map[string]string{"error": "not a valid IP address"},
		}
	}
	return s.respond(req, route), nil
}

// Successful lookups for a set of addresses, which is what most cases want.
func okRoutes(ips ...string) map[string]stubRoute {
	routes := make(map[string]stubRoute, len(ips))
	for _, ip := range ips {
		routes[ip] = stubRoute{body: map[string]any{"ip": ip, "is_vpn": false}}
	}
	return routes
}

// A POST /batch is answered the way the API answers one: every address the
// table knows is a result if its route is a 200 and an entry error otherwise,
// and an unknown address is the 400 the API gives a string that is not one.
// One call however many addresses, which is what the request counts measure.
func (s *stubTransport) batch(req *http.Request) stubRoute {
	var in struct {
		IPs []string `json:"ips"`
	}
	if req.Body != nil {
		raw, _ := io.ReadAll(req.Body)
		_ = json.Unmarshal(raw, &in)
	}
	results := map[string]any{}
	failures := map[string]any{}
	for _, ip := range in.IPs {
		route, ok := s.routes[ip]
		if !ok {
			failures[ip] = map[string]any{"status": http.StatusBadRequest, "error": "not a valid IP address"}
			continue
		}
		if route.status == 0 || route.status == http.StatusOK {
			results[ip] = route.body
			continue
		}
		encoded, _ := json.Marshal(route.body)
		failures[ip] = map[string]any{"status": route.status, "error": messageOf(encoded)}
	}
	return stubRoute{body: map[string]any{"results": results, "errors": failures}}
}

func (s *stubTransport) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func (s *stubTransport) peakInFlight() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peak
}

func (s *stubTransport) enter(url string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, url)
	s.inFlight++
	s.peak = max(s.peak, s.inFlight)
}

func (s *stubTransport) leave() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inFlight--
}

func (s *stubTransport) respond(req *http.Request, route stubRoute) *http.Response {
	body, err := json.Marshal(route.body)
	if err != nil {
		body = []byte(`{"error":"stub could not encode its body"}`)
	}
	header := http.Header{"Content-Type": []string{"application/json"}}
	for name, value := range route.headers {
		header.Set(name, value)
	}
	status := route.status
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    req,
	}
}

// The lookup path is the address itself; anything else is keyed by its path so
// the database endpoints can be routed too.
func stubKey(req *http.Request) string {
	path := strings.TrimPrefix(req.URL.Path, "/")
	if strings.HasPrefix(path, "api/") {
		return "/" + path
	}
	if unescaped, err := url.PathUnescape(path); err == nil {
		return unescaped
	}
	return path
}
