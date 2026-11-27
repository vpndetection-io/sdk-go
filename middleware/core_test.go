// Pins the client New builds when the caller passes none, which is how every
// framework README sets the middleware up.

package middleware_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	vpndetection "github.com/vpndetection-io/sdk-go/v5"
	"github.com/vpndetection-io/sdk-go/v5/middleware"
)

// Outside every bogon block, RFC 5737's documentation ranges included, so the
// lookup cannot be answered locally and has to reach the origin.
const publicIP = "9.9.9.9"

func selectorOf(ip string) middleware.IPSelector[string] {
	return func(string) string { return ip }
}

func TestNewStartsWithOnlyAnAPIKey(t *testing.T) {
	if _, err := middleware.New(middleware.Options[string]{APIKey: "key"}, selectorOf(publicIP)); err != nil {
		t.Fatalf("New with only an APIKey: %v", err)
	}
}

func TestNewStartsWithNoOptions(t *testing.T) {
	if _, err := middleware.New(middleware.Options[string]{}, selectorOf(publicIP)); err != nil {
		t.Fatalf("New with no options: %v", err)
	}
}

// Refused where it is set: every lookup would refuse it, and the middleware
// fail open on every request.
func TestNewRefusesANegativeRetryCount(t *testing.T) {
	retries := -1
	if _, err := middleware.New(middleware.Options[string]{Retries: &retries}, selectorOf(publicIP)); err == nil {
		t.Fatal("New took Retries of -1")
	}
	retries = 0
	if _, err := middleware.New(middleware.Options[string]{Retries: &retries}, selectorOf(publicIP)); err != nil {
		t.Fatalf("New with Retries of 0: %v", err)
	}
}

func TestNewSendsToTheBaseURL(t *testing.T) {
	var requests atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ip":"9.9.9.9","is_vpn":false}`)
	}))
	defer origin.Close()
	core, err := middleware.New(middleware.Options[string]{APIKey: "key", BaseURL: origin.URL}, selectorOf(publicIP))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	lookup, err := core.Evaluate(t.Context(), "request")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if lookup.Err != nil {
		t.Fatalf("lookup failed: %v", lookup.Err)
	}
	if got := requests.Load(); got != 1 {
		t.Errorf("the origin got %d requests, want 1", got)
	}
}

// is_bot is a paid plan's: a condition on it blocks a bot's address from a
// public peer and passes another.
func TestAnIsBotConditionBlocksABotsAddressAndPassesAnother(t *testing.T) {
	for isBot, blocked := range map[string]bool{"true": true, "false": false} {
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ip":"9.9.9.9","is_vpn":false,"is_bot":`+isBot+`}`)
		}))
		core, err := middleware.New(middleware.Options[string]{
			BaseURL:        origin.URL,
			BlockCondition: middleware.Conditions{{"is_bot": true}},
		}, selectorOf(publicIP))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		lookup, err := core.Evaluate(t.Context(), "request")
		origin.Close()
		if err != nil || lookup.Err != nil {
			t.Fatalf("is_bot %s: Evaluate: %v, %v", isBot, err, lookup.Err)
		}
		if lookup.Result.IsBot == nil || *lookup.Result.IsBot != blocked {
			t.Errorf("is_bot %s: attached IsBot = %v, want %v", isBot, lookup.Result.IsBot, blocked)
		}
		if lookup.Blocked != blocked {
			t.Errorf("is_bot %s: Blocked = %v, want %v", isBot, lookup.Blocked, blocked)
		}
	}
}

func TestNewRefusesABaseURLWithNoScheme(t *testing.T) {
	if _, err := middleware.New(middleware.Options[string]{BaseURL: "api.vpndetection.io"}, selectorOf(publicIP)); err == nil {
		t.Error("New accepted a base URL with no scheme")
	}
}

// An Unlimited answer, which carries no is_bot and no type in its AS.
func keylessBody(asnType string) string {
	return `{"ip":"9.9.9.9","is_vpn":false,"is_relay":false,"is_tor":false,"is_anycast":false,` +
		`"asn":{"asn":19281,"name":"Quad9","domain":"quad9.net",` + asnType + `"prefix":"9.9.9.0/24",` +
		`"country":"US","rpki_status":"valid"}}`
}

// serves answers every request with body, and counts them.
func serves(t *testing.T, body string, requests *atomic.Int32) *httptest.Server {
	t.Helper()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(origin.Close)
	return origin
}

// A condition on the AS's type, which an answer without a key leaves out, is
// reported by its path and never matches. The type reads as an empty string
// there, so a condition naming "" would match it if the answer's silence were
// read as a value; the cached answer says the same.
func TestAConditionOnTheASsTypeIsReportedByItsPathWhereTheAnswerLeavesItOut(t *testing.T) {
	var requests atomic.Int32
	origin := serves(t, keylessBody(``), &requests)
	client, err := vpndetection.New(vpndetection.WithBaseURL(origin.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for name, condition := range map[string]middleware.Conditions{
		"a type":        {{"asn": middleware.BlockCondition{"type": "hosting"}}},
		"the empty one": {{"asn": middleware.BlockCondition{"type": ""}}},
		"any of them":   {{"asn": middleware.BlockCondition{"type": middleware.AnyOf("hosting", "")}}},
	} {
		t.Run(name, func(t *testing.T) {
			core, err := middleware.New(middleware.Options[string]{
				Client:         client,
				BlockCondition: condition,
				OnMissingField: middleware.MissingFieldError,
			}, selectorOf(publicIP))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			for range 2 {
				lookup, err := core.Evaluate(t.Context(), "request")
				if err == nil || !strings.Contains(err.Error(), "asn.type") {
					t.Fatalf("Evaluate = %v, %+v, want an error naming asn.type", err, lookup)
				}
			}
			result, err := client.Lookup(t.Context(), publicIP)
			if err != nil {
				t.Fatalf("Lookup: %v", err)
			}
			if middleware.Matches(condition, result) {
				t.Error("a type the answer does not carry matched")
			}
			if missing := middleware.MissingMembers(condition, result); len(missing) != 1 || missing[0] != "asn.type" {
				t.Errorf("MissingMembers = %v, want [asn.type]", missing)
			}
		})
	}
	if got := requests.Load(); got != 1 {
		t.Errorf("the origin got %d requests, want 1: the cached answer must carry what it left out", got)
	}
}

// The same condition under an answer that carries the type blocks on it, so the
// path above is the answer's silence and not the condition's.
func TestAConditionOnTheASsTypeBlocksWhereTheAnswerCarriesIt(t *testing.T) {
	for asnType, blocked := range map[string]bool{`"type":"hosting",`: true, `"type":"isp",`: false} {
		var requests atomic.Int32
		var warnings strings.Builder
		core, err := middleware.New(middleware.Options[string]{
			BaseURL:        serves(t, keylessBody(asnType), &requests).URL,
			BlockCondition: middleware.Conditions{{"asn": middleware.BlockCondition{"type": "hosting"}}},
			Logger:         slog.New(slog.NewTextHandler(&warnings, nil)),
		}, selectorOf(publicIP))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		lookup, err := core.Evaluate(t.Context(), "request")
		if err != nil || lookup.Err != nil {
			t.Fatalf("%s: Evaluate: %v, %v", asnType, err, lookup.Err)
		}
		if lookup.Blocked != blocked {
			t.Errorf("%s: Blocked = %v, want %v", asnType, lookup.Blocked, blocked)
		}
		if warnings.Len() != 0 {
			t.Errorf("%s: warned %q, want nothing: the answer carries the type", asnType, warnings.String())
		}
	}
}

// An is_bot condition on an Unlimited answer, which carries none, is reported
// by name and never matches; a request is not blocked for what its answer left out.
func TestAnIsBotConditionIsReportedWhereTheAnswerLeavesItOut(t *testing.T) {
	var requests atomic.Int32
	core, err := middleware.New(middleware.Options[string]{
		BaseURL:        serves(t, keylessBody(``), &requests).URL,
		BlockCondition: middleware.Conditions{{"is_bot": true}},
		OnMissingField: middleware.MissingFieldError,
	}, selectorOf(publicIP))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if lookup, err := core.Evaluate(t.Context(), "request"); err == nil || !strings.Contains(err.Error(), "is_bot") {
		t.Errorf("Evaluate = %v, %+v, want an error naming is_bot", err, lookup)
	}
}

// A Result built by hand was served in full, so its type reads as the value it
// holds and a condition on it decides.
func TestAResultBuiltByHandHasItsASsTypeServed(t *testing.T) {
	result := &vpndetection.Result{LookupResponse: vpndetection.LookupResponse{
		Asn: &vpndetection.Asn{Type: "hosting"},
	}}
	conditions := middleware.Conditions{{"asn": middleware.BlockCondition{"type": "hosting"}}}
	if !middleware.Matches(conditions, result) {
		t.Error("a hand-built AS of type hosting did not match")
	}
	if missing := middleware.MissingMembers(conditions, result); len(missing) != 0 {
		t.Errorf("MissingMembers = %v, want none", missing)
	}
}
