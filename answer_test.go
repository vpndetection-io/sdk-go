package vpndetection

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
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

// A date-time is read only with a zone RFC 3339 allows. time.Time reads an
// offset hour of 24 and a minute of 60 too, so through v5.9.0 +24:00 was a date
// a day off; every other made-up date it already refused.
func TestADateTimeIsReadOnlyWithAZoneRFC3339Allows(t *testing.T) {
	read := map[string]bool{
		"2026-10-05T10:00:00Z": true, "2026-10-05T10:00:00.123Z": true, "2026-10-05T10:00:00+23:59": true,
		"2026-10-05T10:00:00-00:00": true, "2026-10-05T10:00:00+05:30": true,
		"2026-10-05T10:00:00+24:00": false, "2026-10-05T10:00:00-24:00": false, "2026-10-05T10:00:00+24:59": false,
		"2026-10-05T10:00:00+05:60": false, "2026-10-05T10:00:00+0500": false, "2026-10-05T10:00:00": false,
	}
	answers := map[string]struct {
		body string
		call func(ctx context.Context, c *Client) error
	}{
		"Database.List": {
			`{"databases":[{"name":"vpn_ip","base":"vpn_ip","summary":"s","open":false,"in_term":true,` +
				`"standing":"licensed","license_type":"standard","starts":%q,"expires":null,` +
				`"renews_at":null,"notice_due_at":null,"versions":[]}]}`,
			answeringCalls["Database.List"],
		},
		"Database.Downloads": {
			`{"downloads":[{"dataset_id":"vpn_ip","format":"mmdb","outcome":"ok","sample":false,"open":false,` +
				`"bytes":760,"http_status":302,"apikey_id":"ak_1","client_ip":null,"user_agent":null,"created":%q}]}`,
			answeringCalls["Database.Downloads"],
		},
	}
	for value, want := range read {
		for name, answer := range answers {
			t.Run(name+" given "+value, func(t *testing.T) {
				t.Parallel()
				transport := &fixedTransport{status: http.StatusOK, contentType: "application/json",
					body: fmt.Sprintf(answer.body, value)}
				err := answer.call(t.Context(), fixedClient(t, transport, WithRetries(0)))
				switch {
				case want && err != nil:
					t.Errorf("%v, want the date read", err)
				case !want:
					assertKind(t, err, KindServerError, http.StatusOK)
				}
			})
		}
	}
}

// RFC 3339 lets the T and the Z be lowercase, and time.Time does not, so through
// v5.10.1 a lowercase t or z failed every date-time member as unreadable, while
// a one-digit hour and a comma before the fraction, which RFC 3339 does not
// have, were read as dates.
func TestADateTimeIsReadInRFC3339sFormAlone(t *testing.T) {
	at := time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC)
	read := map[string]time.Time{
		"2026-10-05t10:00:00z": at, "2026-10-05t10:00:00Z": at, "2026-10-05T10:00:00z": at,
		"2026-10-05t15:30:00.5+05:30": at.Add(500 * time.Millisecond),
	}
	refused := []string{
		"2026-10-05T1:00:00Z", "2026-10-05T10:00:00,5Z", "2026-10-05T10:00:00.Z", "2026-10-05T10:00Z",
		"2026-10-05 10:00:00Z", " 2026-10-05T10:00:00Z", "2026-10-05T10:00:00Z\n", "\u0662026-10-05T10:00:00Z",
	}
	answers := map[string]struct {
		body string
		read func(ctx context.Context, c *Client) (time.Time, error)
	}{
		"Database.List": {
			`{"databases":[{"name":"vpn_ip","base":"vpn_ip","summary":"s","open":false,"in_term":true,` +
				`"standing":"licensed","license_type":"standard","starts":%q,"expires":null,` +
				`"renews_at":null,"notice_due_at":null,"versions":[]}]}`,
			func(ctx context.Context, c *Client) (time.Time, error) {
				list, err := c.Database.List(ctx)
				if err != nil {
					return time.Time{}, err
				}
				return *list[0].Starts, nil
			},
		},
		"Database.Downloads": {
			`{"downloads":[{"dataset_id":"vpn_ip","format":"mmdb","outcome":"ok","sample":false,"open":false,` +
				`"bytes":760,"http_status":302,"apikey_id":"ak_1","client_ip":null,"user_agent":null,"created":%q}]}`,
			func(ctx context.Context, c *Client) (time.Time, error) {
				downloads, err := c.Database.Downloads(ctx, 1)
				if err != nil {
					return time.Time{}, err
				}
				return downloads[0].Created, nil
			},
		},
		"MyEntitlement": {
			`{"org_id":"85bb51e4-2eb6-4a31-8e4d-02ba8b98fe61","apikey":{"id":"0ab424cc-7619-4dad-b027-afacdc2cedb0",` +
				`"expires":null,"allowed_cidrs":[]},"plan":{"key":"max","tier":"max"},"usage":{"requests":5,` +
				`"quota":50,"hard_limit":null,"window_start":%q,"window_end":"2026-10-04T07:00:00Z"}}`,
			func(ctx context.Context, c *Client) (time.Time, error) {
				entitlement, err := c.MyEntitlement(ctx)
				if err != nil {
					return time.Time{}, err
				}
				return entitlement.Usage.WindowStart, nil
			},
		},
	}
	for name, answer := range answers {
		for value, want := range read {
			t.Run(name+" reads "+value, func(t *testing.T) {
				t.Parallel()
				transport := &fixedTransport{status: http.StatusOK, contentType: "application/json",
					body: fmt.Sprintf(answer.body, value)}
				got, err := answer.read(t.Context(), fixedClient(t, transport, WithRetries(0)))
				if err != nil || !got.Equal(want) {
					t.Errorf("read %v, %v; want %v", got, err, want)
				}
			})
		}
		for _, value := range refused {
			t.Run(name+" refuses "+value, func(t *testing.T) {
				t.Parallel()
				transport := &fixedTransport{status: http.StatusOK, contentType: "application/json",
					body: fmt.Sprintf(answer.body, value)}
				_, err := answer.read(t.Context(), fixedClient(t, transport, WithRetries(1)))
				assertKind(t, err, KindServerError, http.StatusOK)
				if sent := transport.sent(); sent != 2 {
					t.Errorf("sent %d request(s), want 2", sent)
				}
			})
		}
	}
}

// A number keeps every digit through the walk that respells a date-time.
func TestANumberPastAFloatsPrecisionIsReadExactly(t *testing.T) {
	transport := &fixedTransport{status: http.StatusOK, contentType: "application/json",
		body: `{"databases":[{"name":"vpn_ip","base":"vpn_ip","summary":"s","open":false,"in_term":true,` +
			`"standing":"licensed","license_type":null,"starts":"2026-10-05t10:00:00z","expires":null,` +
			`"renews_at":null,"notice_due_at":null,"versions":[{"id":"vpn_ip_v1","version":1,` +
			`"formats":[{"format":"mmdb","bytes":9007199254740993}]}]}]}`}
	list, err := fixedClient(t, transport, WithRetries(0)).Database.List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got := *list[0].Versions[0].Formats[0].Bytes; got != 9007199254740993 {
		t.Errorf("read %d bytes, want 9007199254740993", got)
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
