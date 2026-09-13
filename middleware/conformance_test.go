// Asserts the middleware half of the shared conformance corpus, which every
// framework middleware in every language asserts. A behaviour that drifts here
// fails here rather than surfacing as two adapters quietly disagreeing about
// the same answer.

package middleware_test

import (
	"encoding/json"
	"os"
	"slices"
	"testing"

	vpndetection "github.com/vpndetection-io/sdk-go"
	"github.com/vpndetection-io/sdk-go/middleware"
)

type corpusData struct {
	Middleware struct {
		Conditions []struct {
			Name      string          `json:"name"`
			Why       string          `json:"why"`
			Bogon     string          `json:"bogon"`
			Body      json.RawMessage `json:"body"`
			Condition json.RawMessage `json:"condition"`
			Expect    struct {
				Blocked bool     `json:"blocked"`
				Missing []string `json:"missing"`
			} `json:"expect"`
		} `json:"conditions"`
		InvalidConditions []struct {
			Name      string          `json:"name"`
			Why       string          `json:"why"`
			Condition json.RawMessage `json:"condition"`
		} `json:"invalidConditions"`
	} `json:"middleware"`
}

func TestCorpusConditions(t *testing.T) {
	for _, c := range corpus(t).Middleware.Conditions {
		t.Run(c.Name, func(t *testing.T) {
			result := resultFor(t, c.Bogon, c.Body)
			conditions := toConditions(t, c.Condition)

			if got := middleware.Matches(conditions, result); got != c.Expect.Blocked {
				t.Errorf("Matches = %v, want %v (%s)", got, c.Expect.Blocked, c.Why)
			}
			missing := middleware.MissingMembers(conditions, result)
			slices.Sort(missing)
			want := slices.Clone(c.Expect.Missing)
			slices.Sort(want)
			if len(missing) != len(want) || !slices.Equal(missing, want) {
				t.Errorf("MissingMembers = %v, want %v (%s)", missing, want, c.Why)
			}
		})
	}
}

func TestCorpusRefusesAConditionThatConstrainsNothing(t *testing.T) {
	for _, c := range corpus(t).Middleware.InvalidConditions {
		t.Run(c.Name, func(t *testing.T) {
			if err := middleware.Validate(toConditions(t, c.Condition)); err == nil {
				t.Errorf("Validate accepted a condition that constrains nothing (%s)", c.Why)
			}
		})
	}
}

func resultFor(t *testing.T, bogon string, body json.RawMessage) *vpndetection.Result {
	t.Helper()
	if bogon != "" {
		// Answered locally, so this needs no transport and pins the
		// synthesized shape rather than a fixture's idea of it.
		client, err := vpndetection.New()
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		result, err := client.Lookup(t.Context(), bogon)
		if err != nil {
			t.Fatalf("Lookup(%q): %v", bogon, err)
		}
		return result
	}
	var response vpndetection.LookupResponse
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("parsing the fixture body: %v", err)
	}
	return &vpndetection.Result{LookupResponse: response}
}

// The corpus is language-neutral JSON, so a bound arrives as an object with
// gte/gt/lte/lt keys and an any-of as an array. Rebuilding them into the Go
// types here is what keeps the corpus readable by twelve languages instead of
// carrying one language's spelling.
func toConditions(t *testing.T, raw json.RawMessage) middleware.Conditions {
	t.Helper()
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("parsing the condition: %v", err)
	}
	if list, ok := value.([]any); ok {
		out := make(middleware.Conditions, 0, len(list))
		for _, entry := range list {
			out = append(out, toCondition(t, entry))
		}
		return out
	}
	return middleware.Conditions{toCondition(t, value)}
}

func toCondition(t *testing.T, value any) middleware.BlockCondition {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("a condition must be an object, got %T", value)
	}
	out := middleware.BlockCondition{}
	for key, entry := range object {
		out[key] = toValue(t, entry)
	}
	return out
}

var boundKeys = []string{"gte", "gt", "lte", "lt"}

func toValue(t *testing.T, value any) any {
	t.Helper()
	switch v := value.(type) {
	case []any:
		return middleware.AnyOf(v...)
	case map[string]any:
		if isBound(v) {
			bound := middleware.Bound{}
			for key, n := range v {
				switch key {
				case "gte":
					bound = bound.Gte(n.(float64))
				case "gt":
					bound = bound.Gt(n.(float64))
				case "lte":
					bound = bound.Lte(n.(float64))
				case "lt":
					bound = bound.Lt(n.(float64))
				}
			}
			return bound
		}
		return toCondition(t, v)
	default:
		return value
	}
}

func isBound(object map[string]any) bool {
	if len(object) == 0 {
		return false
	}
	for key := range object {
		if !slices.Contains(boundKeys, key) {
			return false
		}
	}
	return true
}

func corpus(t *testing.T) corpusData {
	t.Helper()
	raw, err := os.ReadFile("../testdata/testdata.json")
	if err != nil {
		t.Fatalf("reading the corpus: %v", err)
	}
	var data corpusData
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatalf("parsing the corpus: %v", err)
	}
	if len(data.Middleware.Conditions) == 0 {
		t.Fatal("no middleware corpus - run emit.mjs in sdk/common")
	}
	return data
}
