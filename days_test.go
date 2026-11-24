package vpndetection

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

var dayMembers = []string{
	"bot.first_seen", "bot.last_seen", "ssh.first_seen", "ssh.last_seen", "smtp.first_seen", "smtp.last_seen",
	"web.first_seen", "web.last_seen", "dns_resolver.first_seen", "dns_resolver.last_seen",
	"bittorrent.first_seen", "bittorrent.last_seen",
}

// A whole answer carrying every detail with a day, each day as served unless
// set names its member ("ssh.last_seen", "web.first_seen" for the first port).
func dayAnswer(t *testing.T, set map[string]string) string {
	t.Helper()
	details := map[string]map[string]any{
		"bot": {"provider": "google", "provider_name": "Google", "agents": []string{"Googlebot"},
			"categories": []string{"search"}, "verified": true, "identity": "googlebot", "verified_by": "published_list",
			"confidence": "high", "first_seen": "2026-08-04", "last_seen": "2026-11-15"},
		"ssh": {"port": 22, "banner": "SSH-2.0-OpenSSH_9.6p1", "host_key_fp": "SHA256:9Bq3Jrm6pVJ7QqV2c8l0pE6f8wJ4sZ4u5tYyH9cXo1E",
			"session_ok": true, "first_seen": "2026-08-04", "last_seen": "2026-11-15"},
		"smtp": {"port": 25, "banner": "220 mail.example.com ESMTP Postfix", "session_ok": true,
			"first_seen": "2026-08-04", "last_seen": "2026-11-15"},
		"web": {"port": 443, "tls_ok": true, "session_ok": true, "status_code": 200, "server": "nginx", "location": "",
			"title": "Welcome to nginx!", "cert_subject_cn": "example.com", "cert_subject_o": "",
			"cert_issuer_dn": "CN=R11,O=Let's Encrypt,C=US", "cert_browser_trusted": true, "tls_version": "TLS 1.3",
			"first_seen": "2026-08-04", "last_seen": "2026-11-15"},
		"dns_resolver": {"port": 53, "recursion_available": true, "rcode": 0, "answer_correct": true,
			"first_seen": "2026-08-04", "last_seen": "2026-11-15"},
		"bittorrent": {"verified": true, "id_matches_ip": false, "first_seen": "2026-08-21", "last_seen": "2026-11-15",
			"last_reachable": "", "days_seen": 37, "num_ports": 4, "peak_num_ports": 2, "indexer": false,
			"clients": []string{"qB", "TR"}},
	}
	for member, value := range set {
		detail, name, _ := strings.Cut(member, ".")
		details[detail][name] = value
	}
	answer := map[string]any{"ip": "45.83.91.1", "is_vpn": false, "is_bot": true, "is_ssh": true, "is_smtp": true,
		"is_web": true, "is_dns_resolver": true, "is_bittorrent": true, "web": []any{details["web"]}}
	for detail, fields := range details {
		if detail != "web" {
			answer[detail] = fields
		}
	}
	body, err := json.Marshal(answer)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// Refuses body as an unreadable answer, retried, from a lookup, MyIP and a batch
// entry, the batch's other address still read.
func assertDayRefused(t *testing.T, body string) {
	t.Helper()
	for _, call := range []string{"Lookup", "MyIP"} {
		transport := &fixedTransport{status: http.StatusOK, contentType: "application/json", body: body}
		assertKind(t, answeringCalls[call](t.Context(), fixedClient(t, transport)), KindServerError, http.StatusOK)
		if got := transport.sent(); got != 2 {
			t.Errorf("%s sent %d requests, want 2", call, got)
		}
	}
	transport := &fixedTransport{status: http.StatusOK, contentType: "application/json", body: `{"results":{` +
		`"45.83.91.1":` + body + `,"45.83.91.2":` + dayAnswer(t, nil) + `},"errors":{}}`}
	answers, err := fixedClient(t, transport).LookupBatch(t.Context(), []string{"45.83.91.1", "45.83.91.2"})
	if err != nil {
		t.Fatalf("LookupBatch: %v", err)
	}
	assertKind(t, answers["45.83.91.1"].Err, KindServerError, http.StatusOK)
	if got := answers["45.83.91.2"]; got.Err != nil || *got.Result.SSH.LastSeen != "2026-11-15" {
		t.Errorf("45.83.91.2 = %+v, want its answer", got)
	}
}

// The days spec 2026.11.23 formats as dates are read only as a day, in the
// form YYYY-MM-DD, that exists. Through v5.20.0 any string was read.
func TestADetailsDayIsReadOnlyAsADay(t *testing.T) {
	transport := &fixedTransport{status: http.StatusOK, contentType: "application/json", body: dayAnswer(t, nil)}
	result, err := fixedClient(t, transport).Lookup(t.Context(), "45.83.91.1")
	if err != nil {
		t.Fatalf("Lookup of a whole answer: %v", err)
	}
	read := []string{*result.Bot.FirstSeen, *result.SSH.LastSeen, *result.SMTP.LastSeen, (*result.Web)[0].FirstSeen,
		*result.DNSResolver.LastSeen, *result.Bittorrent.FirstSeen}
	want := []string{"2026-08-04", "2026-11-15", "2026-11-15", "2026-08-04", "2026-11-15", "2026-08-21"}
	if strings.Join(read, " ") != strings.Join(want, " ") {
		t.Fatalf("read %v, want %v", read, want)
	}
	for _, value := range []string{"x", "tomorrow", "monday", "2026-02-30", "2026-11-15T24:00",
		"2026-11-15T10:00:00Z", "2026-11-15+05", "2026-11-15\n", "2026-11-1٥", "2026-11-15 ", "2026-1-15", ""} {
		t.Run("ssh.last_seen "+value, func(t *testing.T) {
			assertDayRefused(t, dayAnswer(t, map[string]string{"ssh.last_seen": value}))
		})
	}
}

func TestEveryDetailsDayRefusesAMalformedDay(t *testing.T) {
	for _, member := range dayMembers {
		t.Run(member, func(t *testing.T) {
			assertDayRefused(t, dayAnswer(t, map[string]string{member: "x"}))
		})
	}
}
