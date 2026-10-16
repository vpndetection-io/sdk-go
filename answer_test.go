package vpndetection

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
)

// Answers every request with one fixed response, its body bytes exactly as
// given, and counts the requests: what a proxy in front of the API, or an API
// having a bad day, sends back.
type fixedTransport struct {
	status      int
	contentType string
	body        string
	mu          sync.Mutex
	requests    int
	auth        []string
}

func (f *fixedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.requests++
	f.auth = append(f.auth, req.Header.Get("Authorization"))
	f.mu.Unlock()
	header := http.Header{}
	if f.contentType != "" {
		header.Set("Content-Type", f.contentType)
	}
	return &http.Response{
		StatusCode: f.status,
		Status:     http.StatusText(f.status),
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader([]byte(f.body))),
		Request:    req,
	}, nil
}

func (f *fixedTransport) sent() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
}

// Every call that reads a JSON answer, each reduced to its error. A batch's is
// the error its first address carries.
var answeringCalls = map[string]func(ctx context.Context, c *Client) error{
	"Lookup": func(ctx context.Context, c *Client) error {
		_, err := c.Lookup(ctx, "45.83.91.1")
		return err
	},
	"MyIP": func(ctx context.Context, c *Client) error {
		_, err := c.MyIP(ctx)
		return err
	},
	"MyEntitlement": func(ctx context.Context, c *Client) error {
		_, err := c.MyEntitlement(ctx)
		return err
	},
	"LookupBatch": func(ctx context.Context, c *Client) error {
		answers, err := c.LookupBatch(ctx, []string{"45.83.91.1", "45.83.91.2"})
		if err != nil {
			return err
		}
		return answers["45.83.91.1"].Err
	},
	"Database.List": func(ctx context.Context, c *Client) error {
		_, err := c.Database.List(ctx)
		return err
	},
	"Database.Metadata": func(ctx context.Context, c *Client) error {
		_, err := c.Database.Metadata(ctx, "vpn_ip")
		return err
	},
	"Database.Checksums": func(ctx context.Context, c *Client) error {
		_, err := c.Database.Checksums(ctx, "vpn_ip", FormatMMDB)
		return err
	},
	"Database.Downloads": func(ctx context.Context, c *Client) error {
		_, err := c.Database.Downloads(ctx, 5)
		return err
	},
	"Oauth.Metadata": func(ctx context.Context, c *Client) error {
		_, err := c.Oauth.Metadata(ctx)
		return err
	},
	"Oauth.DeviceAuthorization": func(ctx context.Context, c *Client) error {
		_, err := c.Oauth.DeviceAuthorization(ctx, "cid", DeviceAuthorizationOptions{})
		return err
	},
}

func fixedClient(t *testing.T, transport *fixedTransport, opts ...Option) *Client {
	t.Helper()
	client, err := New(append([]Option{
		WithHTTPClient(&http.Client{Transport: transport}), WithoutCache(), WithRetries(1),
	}, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

func assertKind(t *testing.T, err error, kind ErrorKind, status int) {
	t.Helper()
	var apiErr *Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v (%T), want an *Error", err, err)
	}
	if apiErr.Kind != kind || apiErr.StatusCode != status {
		t.Errorf("err = %s with status %d, want %s with status %d", apiErr.Kind, apiErr.StatusCode, kind, status)
	}
}

// A 2xx a call cannot read as its answer is the server failing, so it is the
// SDK's own server_error, carrying the status, and retried like a 5xx. Through
// v5.5.2 an HTML page was a bad_request sent once, `[]` or an empty body a
// network error with no status, and `{}` or `null` an answer of zero values.
func TestAnUnreadable2xxIsARetriedServerErrorCarryingItsStatus(t *testing.T) {
	bodies := map[string]struct{ contentType, body string }{
		"an HTML page":                 {"text/html", "<html>proxy</html>"},
		"an HTML page labeled as JSON": {"application/json", "<html>proxy</html>"},
		"an empty body":                {"application/json", ""},
		"null":                         {"application/json", "null"},
		"an array":                     {"application/json", "[]"},
		"an empty object":              {"application/json", "{}"},
		"a string":                     {"application/json", `"ok"`},
	}
	for name, call := range answeringCalls {
		for what, body := range bodies {
			t.Run(name+" given "+what, func(t *testing.T) {
				t.Parallel()
				transport := &fixedTransport{status: http.StatusOK, contentType: body.contentType, body: body.body}
				assertKind(t, call(t.Context(), fixedClient(t, transport)), KindServerError, http.StatusOK)
				if got := transport.sent(); got != 2 {
					t.Errorf("sent %d requests, want 2: the answer is retried", got)
				}
			})
		}
	}
}

// A 200 on the download link is not the redirect it hands back. Through v5.5.2
// it was a bad_request sent once.
func TestADownloadLinkAnsweredWithA2xxIsARetriedServerError(t *testing.T) {
	transport := &fixedTransport{status: http.StatusOK, contentType: "application/json", body: `{"url":"x"}`}
	_, err := fixedClient(t, transport).Database.DownloadURL(t.Context(), "vpn_ip", FormatMMDB)
	assertKind(t, err, KindServerError, http.StatusOK)
	if got := transport.sent(); got != 2 {
		t.Errorf("sent %d requests, want 2", got)
	}
}

// A member the spec requires, sent as null, missing or of the wrong type, makes
// the answer unreadable. json.Unmarshal reads a null or missing member as its
// zero value, so through v5.5.2 a lookup of `"ip": null` answered an empty
// address and a catalog of `[{}]` a database with no name.
func TestAnAnswerMissingARequiredMemberIsUnreadable(t *testing.T) {
	cases := []struct {
		call, body string
	}{
		{"Lookup", `{"ip":null,"is_vpn":false}`},
		{"Lookup", `{"ip":"45.83.91.1"}`},
		{"Lookup", `{"ip":"45.83.91.1","is_vpn":"yes"}`},
		{"MyIP", `{"ip":"45.83.91.1","is_vpn":null}`},
		{"Database.List", `{"databases":null}`},
		{"Database.List", `{"databases":[{}]}`},
		{"Database.List", `{"databases":[null]}`},
		{"Database.Downloads", `{"downloads":"none"}`},
		{"Database.Checksums", `{"id":"vpn_ip","format":"mmdb","checksums":null}`},
		{"Oauth.Metadata", `{"issuer":null,"authorization_endpoint":"a","token_endpoint":"t"}`},
		{"Oauth.Metadata", `{"issuer":5,"authorization_endpoint":"a","token_endpoint":"t"}`},
	}
	for _, c := range cases {
		t.Run(c.call+" "+c.body, func(t *testing.T) {
			t.Parallel()
			transport := &fixedTransport{status: http.StatusOK, contentType: "application/json", body: c.body}
			assertKind(t, answeringCalls[c.call](t.Context(), fixedClient(t, transport)), KindServerError, http.StatusOK)
			if got := transport.sent(); got != 2 {
				t.Errorf("sent %d requests, want 2", got)
			}
		})
	}
}

// A batch entry the client cannot read is that address's error alone, and the
// chunk's other answers stand. Through v5.5.2 one such entry failed every
// address in the chunk as a network error, and a missing `ip` was answered.
func TestABatchEntryItCannotReadIsThatAddressesErrorAlone(t *testing.T) {
	for _, entry := range []string{`"x"`, `{"is_vpn":false}`, `null`} {
		t.Run(entry, func(t *testing.T) {
			transport := &fixedTransport{status: http.StatusOK, contentType: "application/json", body: `{"results":{` +
				`"45.83.91.1":{"ip":"45.83.91.1","is_vpn":true},"45.83.91.2":` + entry + `},"errors":{}}`}
			answers, err := fixedClient(t, transport).LookupBatch(t.Context(), []string{"45.83.91.1", "45.83.91.2"})
			if err != nil {
				t.Fatalf("LookupBatch: %v", err)
			}
			if got := answers["45.83.91.1"]; got.Err != nil || got.Result == nil || !got.Result.IsVpn {
				t.Errorf("45.83.91.1 = %+v, want its answer", got)
			}
			assertKind(t, answers["45.83.91.2"].Err, KindServerError, http.StatusOK)
			if got := transport.sent(); got != 1 {
				t.Errorf("sent %d requests, want 1: an entry is never retried on its own", got)
			}
		})
	}
}

// A 4xx is classified by its status before anything decodes its body, so a
// proxy's page labeled as JSON is the refusal it is, sent once. Through v5.5.2
// the generated parsers decoded it first, so a JSON-labeled HTML 401 on MyIP,
// MyEntitlement or a database call was a network error retried twice.
func TestA4xxWhoseBodyIsNotTheAPIsIsClassifiedByItsStatus(t *testing.T) {
	cases := []struct {
		status int
		body   string
		kind   ErrorKind
	}{
		{http.StatusUnauthorized, "<html>401</html>", KindUnauthorized},
		{http.StatusForbidden, "", KindForbidden},
		{http.StatusNotFound, "<html>404</html>", KindBadRequest},
		{http.StatusTooManyRequests, "<html>429</html>", KindQuotaExceeded},
	}
	calls := map[string]func(ctx context.Context, c *Client) error{
		"Database.DownloadURL": func(ctx context.Context, c *Client) error {
			_, err := c.Database.DownloadURL(ctx, "vpn_ip", FormatMMDB)
			return err
		},
	}
	for name, call := range answeringCalls {
		calls[name] = call
	}
	for name, call := range calls {
		for _, c := range cases {
			t.Run(name+" "+http.StatusText(c.status), func(t *testing.T) {
				t.Parallel()
				transport := &fixedTransport{status: c.status, contentType: "application/json", body: c.body}
				assertKind(t, call(t.Context(), fixedClient(t, transport)), c.kind, c.status)
				if got := transport.sent(); got != 1 {
					t.Errorf("sent %d requests, want 1", got)
				}
			})
		}
	}
}
