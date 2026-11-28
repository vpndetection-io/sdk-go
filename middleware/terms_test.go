// A block condition's term types: what reads as a term, and what New refuses
// because no answer could ever match it, which blocks nobody and says nothing.

package middleware_test

import (
	"math"
	"strings"
	"testing"

	vpndetection "github.com/vpndetection-io/sdk-go/v5"
	"github.com/vpndetection-io/sdk-go/v5/middleware"
)

const vpnAnswer = `{"ip":"45.83.91.1","is_vpn":true,"is_relay":false,"is_tor":false,"relay":{},"tor":{},` +
	`"vpn":{"provider":"nordvpn","confidence":"high","method":"rdns","last_seen":"2026-09-01"},` +
	`"resproxy":{"provider":"brightdata","first_seen":"2026-06-01","last_seen":"2026-09-01","hits":7,` +
	`"hits_days_pct":42,"providers_num":2},"is_resproxy":true,` +
	`"user_agent":{"agent":"Googlebot","kind":"bot","verdict":"spoofed"}}`

type confidenceLevel string

type signalCount int

type enabled bool

func TestAListOfTermsIsAnyOfLikeAnyOf(t *testing.T) {
	result := resultFor(t, "", []byte(vpnAnswer))
	cases := []struct {
		name string
		term any
		want bool
	}{
		{"strings holding it", []string{"high", "medium"}, true},
		{"strings without it", []string{"low", "medium"}, false},
		{"strings in another case", []string{"LOW", "High"}, true},
		{"any holding it", []any{"low", "high"}, true},
		{"any without it", []any{"low"}, false},
		{"an array holding it", [2]string{"medium", "high"}, true},
		{"a named string slice", []confidenceLevel{"high"}, true},
		{"a named string", confidenceLevel("HIGH"), true},
		{"a named string not held", confidenceLevel("low"), false},
		{"AnyOf", middleware.AnyOf("high", "medium"), true},
		{"a slice in a slice", []any{[]string{"low"}, []string{"high"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conditions := middleware.Conditions{{"vpn": middleware.BlockCondition{"confidence": tc.term}}}
			if err := middleware.Validate(conditions); err != nil {
				t.Fatalf("Validate refused %T: %v", tc.term, err)
			}
			if got := middleware.Matches(conditions, result); got != tc.want {
				t.Errorf("Matches = %v, want %v", got, tc.want)
			}
			if missing := middleware.MissingMembers(conditions, result); len(missing) != 0 {
				t.Errorf("MissingMembers = %v, want none", missing)
			}
		})
	}
}

func TestANumberTermIsComparedWhateverItsType(t *testing.T) {
	result := resultFor(t, "", []byte(vpnAnswer))
	for name, term := range map[string]any{
		"an int":          7,
		"a float":         7.0,
		"a named int":     signalCount(7),
		"a list of ints":  []int{5, 7},
		"a list of mixed": []any{5.5, 7},
	} {
		t.Run(name, func(t *testing.T) {
			conditions := middleware.Conditions{{"resproxy": middleware.BlockCondition{"hits": term}}}
			if err := middleware.Validate(conditions); err != nil {
				t.Fatalf("Validate refused %T: %v", term, err)
			}
			if !middleware.Matches(conditions, result) {
				t.Errorf("hits 7 did not match %v", term)
			}
		})
	}
}

// The SDK's own constant is a defined string type, so a condition written with
// it is the first thing a caller reaches for.
func TestTheSDKsVerdictConstantIsATerm(t *testing.T) {
	result := resultFor(t, "", []byte(vpnAnswer))
	conditions := middleware.Conditions{
		{"user_agent": middleware.BlockCondition{"verdict": vpndetection.VerdictSpoofed}},
	}
	if err := middleware.Validate(conditions); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !middleware.Matches(conditions, result) {
		t.Error("a spoofed verdict did not match VerdictSpoofed")
	}
	other := middleware.Conditions{
		{"user_agent": middleware.BlockCondition{"verdict": vpndetection.VerdictVerified}},
	}
	if middleware.Matches(other, result) {
		t.Error("a spoofed verdict matched VerdictVerified")
	}
}

func TestATermNoAnswerCouldMatchIsRefusedWhereTheConditionIsBuilt(t *testing.T) {
	high := "high"
	cases := map[string]any{
		"a pointer":                   &high,
		"a nil pointer":               (*string)(nil),
		"a plain map":                 map[string]any{"provider": "nordvpn"},
		"a struct":                    struct{ Confidence string }{"high"},
		"a function":                  func() {},
		"a channel":                   make(chan int),
		"a complex number":            complex(1, 2),
		"a zero Bound":                middleware.Bound{},
		"a Bound with a NaN limit":    middleware.Gte(math.NaN()),
		"a zero Bound in AnyOf":       middleware.AnyOf("high", middleware.Bound{}),
		"a zero Bound in a slice":     []any{middleware.Bound{}},
		"a nil in AnyOf":              middleware.AnyOf("high", nil),
		"a nil in a slice":            []any{"high", nil},
		"a pointer in a slice":        []*string{&high},
		"a plain map in AnyOf":        middleware.AnyOf(map[string]any{"provider": "nordvpn"}),
		"a pointer in a nested slice": []any{[]any{&high}},
	}
	for name, term := range cases {
		t.Run(name, func(t *testing.T) {
			conditions := middleware.Conditions{{"vpn": middleware.BlockCondition{"confidence": term}}}
			err := middleware.Validate(conditions)
			if err == nil {
				t.Fatalf("Validate took %T, which no answer matches", term)
			}
			if !strings.Contains(err.Error(), "vpn.confidence") {
				t.Errorf("the refusal %q does not name the member", err)
			}
			if _, err := middleware.New(middleware.Options[string]{BlockCondition: conditions}, selectorOf(publicIP)); err == nil {
				t.Errorf("New took %T", term)
			}
		})
	}
}

// A zero Bound is a term that holds for every number, so beside a real one it
// would read as a constraint and match as none.
func TestAZeroBoundBesideAnotherTermIsStillRefused(t *testing.T) {
	conditions := middleware.Conditions{{
		"is_vpn":   true,
		"resproxy": middleware.BlockCondition{"hits": middleware.Bound{}},
	}}
	if err := middleware.Validate(conditions); err == nil {
		t.Fatal("Validate took a zero Bound beside is_vpn")
	}
	conditions = middleware.Conditions{{"is_vpn": true}, {"resproxy": middleware.BlockCondition{"hits": middleware.Bound{}}}}
	if err := middleware.Validate(conditions); err == nil {
		t.Fatal("Validate took a zero Bound in the second condition of a list")
	}
}

func TestAnEmptyListOfTermsConstrainsNothing(t *testing.T) {
	for name, term := range map[string]any{
		"AnyOf()":       middleware.AnyOf(),
		"an empty list": []string{},
		"a nil list":    []string(nil),
	} {
		t.Run(name, func(t *testing.T) {
			alone := middleware.Conditions{{"vpn": middleware.BlockCondition{"confidence": term}}}
			if err := middleware.Validate(alone); err == nil {
				t.Errorf("Validate took %s as the only term", name)
			}
			beside := middleware.Conditions{{"is_vpn": true, "vpn": middleware.BlockCondition{"confidence": term}}}
			if err := middleware.Validate(beside); err != nil {
				t.Errorf("Validate refused %s beside a term: %v", name, err)
			}
			if !middleware.Matches(beside, resultFor(t, "", []byte(vpnAnswer))) {
				t.Errorf("%s beside is_vpn: true stopped it matching", name)
			}
		})
	}
}

// A defined bool is compared as a bool, and its false is ignored as false is.
func TestADefinedBoolIsABoolTerm(t *testing.T) {
	result := resultFor(t, "", []byte(vpnAnswer))
	if err := middleware.Validate(middleware.Conditions{{"is_vpn": enabled(false)}}); err == nil {
		t.Error("Validate took a defined false as the only term")
	}
	conditions := middleware.Conditions{{"is_vpn": enabled(true), "is_tor": enabled(false)}}
	if err := middleware.Validate(conditions); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !middleware.Matches(conditions, result) {
		t.Error("is_vpn: true did not match beside an ignored false")
	}
}

func TestEveryTermTypeTheContractNamesIsAccepted(t *testing.T) {
	ok := middleware.Conditions{
		{"is_vpn": true},
		{"vpn": middleware.BlockCondition{"provider": "nordvpn", "confidence": []string{"high"}}},
		{"resproxy": middleware.BlockCondition{"hits": middleware.Gte(5).Lt(100)}},
		{"resproxy": middleware.BlockCondition{"hits": middleware.AnyOf(middleware.Gte(5), 3)}},
		{"resproxy": middleware.BlockCondition{"hits": float32(7)}},
		{"is_tor": false, "is_vpn": nil, "is_relay": true},
	}
	if err := middleware.Validate(ok); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}
