package vpndetection

import (
	"fmt"
	"net/http"
	"reflect"
	"testing"
)

// An Unlimited answer, which carries no is_bot and no type in its AS.
const keylessAnswer = `{"ip":"45.83.91.1","is_vpn":false,"is_relay":false,"is_tor":false,"is_anycast":false,` +
	`"asn":{"asn":9009,"name":"M247 Europe SRL","domain":"m247global.com","prefix":"45.83.91.0/24",` +
	`"country":"RO","rpki_status":"valid"}}`

func withASType(typeMember string) string {
	return fmt.Sprintf(`{"ip":"45.83.91.1","is_vpn":false,"asn":{"asn":9009,"name":"M247 Europe SRL",`+
		`"domain":"m247global.com",%s"prefix":"45.83.91.0/24","country":"RO","rpki_status":"valid"}}`, typeMember)
}

// Unlimited's answer stopped carrying the AS's type on spec 2026.11.26, and a
// client that required it failed every keyless lookup. The type keeps the plain
// string it had, so its absence reads as empty.
func TestAKeylessAnswerWithoutTheASsTypeIsRead(t *testing.T) {
	for _, call := range []string{"Lookup", "MyIP"} {
		t.Run(call, func(t *testing.T) {
			transport := &fixedTransport{status: http.StatusOK, contentType: "application/json", body: keylessAnswer}
			if err := answeringCalls[call](t.Context(), fixedClient(t, transport)); err != nil {
				t.Fatalf("%s of an answer without the AS's type: %v", call, err)
			}
		})
	}
	transport := &fixedTransport{status: http.StatusOK, contentType: "application/json", body: keylessAnswer}
	result, err := fixedClient(t, transport).Lookup(t.Context(), "45.83.91.1")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if result.Asn.Type != "" || result.Asn.Asn != 9009 || result.Asn.Name != "M247 Europe SRL" || *result.Asn.Country != "RO" {
		t.Errorf("Asn = %+v, want its members read and an empty Type", result.Asn)
	}
	if result.IsBot != nil {
		t.Errorf("IsBot = %v, want nil: the answer carries none", *result.IsBot)
	}
}

func TestABatchEntryWithoutTheASsTypeIsRead(t *testing.T) {
	transport := &fixedTransport{status: http.StatusOK, contentType: "application/json", body: `{"results":{` +
		`"45.83.91.1":` + keylessAnswer + `,"45.83.91.2":` + withASType(`"type":"hosting",`) + `},"errors":{}}`}
	answers, err := fixedClient(t, transport).LookupBatch(t.Context(), []string{"45.83.91.1", "45.83.91.2"})
	if err != nil {
		t.Fatalf("LookupBatch: %v", err)
	}
	if got := answers["45.83.91.1"]; got.Err != nil || got.Result.Asn.Asn != 9009 || got.Result.Asn.Type != "" {
		t.Errorf("45.83.91.1 = %+v, want its answer with an empty Type", got)
	}
	if got := answers["45.83.91.2"]; got.Err != nil || got.Result.Asn.Type != "hosting" {
		t.Errorf("45.83.91.2 = %+v, want its answer with its Type", got)
	}
}

// The type's public type is a string, so a caller reading it keeps compiling.
func TestTheASsTypeKeepsItsPublicType(t *testing.T) {
	field, ok := reflect.TypeFor[Asn]().FieldByName("Type")
	if !ok || field.Type.Kind() != reflect.String {
		t.Errorf("Asn.Type = %v, want a plain string", field.Type)
	}
}

// A type that is present is read as served; one of the wrong JSON type, or
// null, is still an answer the client refuses, as any member the spec lists.
func TestAPresentASTypeIsReadAsServedAndAWrongOneIsUnreadable(t *testing.T) {
	transport := &fixedTransport{status: http.StatusOK, contentType: "application/json", body: withASType(`"type":"hosting",`)}
	result, err := fixedClient(t, transport).Lookup(t.Context(), "45.83.91.1")
	if err != nil || result.Asn.Type != "hosting" {
		t.Fatalf("Lookup = %+v, %v, want the type served", result, err)
	}
	for _, member := range []string{`"type":null,`, `"type":5,`, `"type":true,`, `"type":{},`, `"type":["hosting"],`} {
		t.Run(member, func(t *testing.T) {
			body := withASType(member)
			for _, call := range []string{"Lookup", "MyIP"} {
				transport := &fixedTransport{status: http.StatusOK, contentType: "application/json", body: body}
				assertKind(t, answeringCalls[call](t.Context(), fixedClient(t, transport)), KindServerError, http.StatusOK)
				if got := transport.sent(); got != 2 {
					t.Errorf("%s sent %d requests, want 2", call, got)
				}
			}
			transport := &fixedTransport{status: http.StatusOK, contentType: "application/json", body: `{"results":{` +
				`"45.83.91.1":` + body + `,"45.83.91.2":` + keylessAnswer + `},"errors":{}}`}
			answers, err := fixedClient(t, transport).LookupBatch(t.Context(), []string{"45.83.91.1", "45.83.91.2"})
			if err != nil {
				t.Fatalf("LookupBatch: %v", err)
			}
			assertKind(t, answers["45.83.91.1"].Err, KindServerError, http.StatusOK)
			if got := answers["45.83.91.2"]; got.Err != nil {
				t.Errorf("45.83.91.2 = %+v, want its answer", got)
			}
		})
	}
}
