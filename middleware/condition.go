// Package middleware holds the framework-agnostic half of a web middleware:
// resolve a client address, classify it, and decide whether to block.
//
// A framework adapter - sdk-go-nethttp, sdk-go-gin - keeps only the parts that
// are genuinely framework-shaped and shares everything here, so the shared
// conformance corpus is asserted once for Go rather than once per framework.
package middleware

import (
	"fmt"
	"reflect"
	"strings"

	vpndetection "github.com/vpndetection-io/sdk-go"
)

// BlockCondition is what makes a request worth blocking, written in the shape
// of a Result and keyed by the wire's own names.
//
// Only the members you name are considered, and they must all hold. A member
// set to false or nil is ignored entirely - a condition states the positive
// signals you act on, so there is no way to write "block when this is false",
// which would otherwise read as blocking everybody.
//
//	middleware.BlockCondition{"is_vpn": true}
//	middleware.BlockCondition{"is_vpn": true, "vpn": middleware.BlockCondition{"provider": "nordvpn"}}
//	middleware.BlockCondition{"resproxy": middleware.BlockCondition{"hits": middleware.Gte(5)}}
//	middleware.BlockCondition{"vpn": middleware.BlockCondition{"confidence": middleware.AnyOf("high", "medium")}}
//
// A value may be a scalar (equality, strings without regard to case), an AnyOf,
// a Bound, or a nested BlockCondition.
type BlockCondition map[string]any

// Conditions is a list of conditions, any one of which blocking is enough.
type Conditions []BlockCondition

// Bound compares a numeric member. Every field set must hold, so two of them
// are a range: Gte(5).Lt(100).
type Bound struct {
	GteV *float64
	GtV  *float64
	LteV *float64
	LtV  *float64
}

// Gte bounds a member at or above v.
func Gte(v float64) Bound { return Bound{GteV: &v} }

// Gt bounds a member strictly above v.
func Gt(v float64) Bound { return Bound{GtV: &v} }

// Lte bounds a member at or below v.
func Lte(v float64) Bound { return Bound{LteV: &v} }

// Lt bounds a member strictly below v.
func Lt(v float64) Bound { return Bound{LtV: &v} }

// Gte narrows an existing bound, so Gte(5).Lt(100) is a range.
func (b Bound) Gte(v float64) Bound { b.GteV = &v; return b }

// Gt narrows an existing bound.
func (b Bound) Gt(v float64) Bound { b.GtV = &v; return b }

// Lte narrows an existing bound.
func (b Bound) Lte(v float64) Bound { b.LteV = &v; return b }

// Lt narrows an existing bound.
func (b Bound) Lt(v float64) Bound { b.LtV = &v; return b }

// AnyOf matches a member equal to any one of these, for an enum-like field.
func AnyOf(values ...any) anyOf { return anyOf(values) }

type anyOf []any

// Matches reports whether an answer satisfies the condition and should
// therefore be blocked.
func Matches(conditions Conditions, result *vpndetection.Result) bool {
	value := reflect.ValueOf(result).Elem()
	for _, one := range conditions {
		if matchesStruct(one, value) {
			return true
		}
	}
	return false
}

// MissingMembers names the top-level members a condition asks about that this
// answer did not carry.
//
// A field your plan does not include is absent rather than false, so a
// condition naming one can never match and the block would silently never fire.
// Gating is per top-level member, which is why only the first path segment is
// checked: a detail object present but empty is a real answer meaning the flag
// is false, not a plan gap.
//
// A locally answered bogon needs no special case: it is synthesized in the
// widest shape, so every member is present and nothing reads as missing.
func MissingMembers(conditions Conditions, result *vpndetection.Result) []string {
	value := reflect.ValueOf(result).Elem()
	seen := map[string]bool{}
	var missing []string
	for _, one := range conditions {
		for member, want := range one {
			if ConstraintCount(want) == 0 || seen[member] {
				continue
			}
			field, ok := fieldFor(value, member)
			if !ok || isAbsent(field) {
				seen[member] = true
				missing = append(missing, member)
			}
		}
	}
	return missing
}

// Validate refuses a condition that constrains nothing.
//
// Ignoring false means BlockCondition{"is_vpn": false} and an empty one have no
// terms left to satisfy, so they would match every answer and block all
// traffic. Nobody writes that on purpose, and failing when the middleware is
// built beats discovering it in production.
func Validate(conditions Conditions) error {
	if len(conditions) == 0 {
		return nil
	}
	for _, one := range conditions {
		if ConstraintCount(one) == 0 {
			return fmt.Errorf(
				"vpndetection: block condition constrains nothing, which would block every "+
					"request; a member set to false or nil is ignored, so state the positive "+
					"signals you act on (got %v)", map[string]any(one))
		}
	}
	return nil
}

// ConstraintCount reports how many leaf constraints a condition carries.
func ConstraintCount(condition any) int {
	switch v := condition.(type) {
	case nil:
		return 0
	case bool:
		if !v {
			return 0
		}
		return 1
	case BlockCondition:
		n := 0
		for _, entry := range v {
			n += ConstraintCount(entry)
		}
		return n
	case Conditions:
		n := 0
		for _, entry := range v {
			n += ConstraintCount(entry)
		}
		return n
	case anyOf:
		return len(v)
	default:
		return 1
	}
}

func matchesStruct(condition BlockCondition, value reflect.Value) bool {
	for member, want := range condition {
		if ConstraintCount(want) == 0 {
			continue
		}
		field, ok := fieldFor(value, member)
		if !ok || !matchesValue(want, deref(field)) {
			return false
		}
	}
	return true
}

// An ABSENT member arrives here as an invalid reflect.Value, because deref of a
// nil pointer yields one. Every branch below must therefore reject a value
// whose Kind does not match, which is what makes "not in your plan" fail a
// match rather than pass it. A new branch that skips that check would silently
// let an unserved member block a request.
func matchesValue(want any, got reflect.Value) bool {
	switch w := want.(type) {
	case anyOf:
		for _, entry := range w {
			if matchesValue(entry, got) {
				return true
			}
		}
		return false
	case Bound:
		return matchesBound(w, got)
	case BlockCondition:
		if got.Kind() != reflect.Struct {
			return false
		}
		return matchesStruct(w, got)
	case string:
		// Providers are lowercase slugs on the wire and a caller should not
		// have to know that, so a string compares without case.
		return got.Kind() == reflect.String && strings.EqualFold(w, got.String())
	case bool:
		return got.Kind() == reflect.Bool && got.Bool() == w
	default:
		if n, ok := asFloat(reflect.ValueOf(want)); ok {
			m, ok := asFloat(got)
			return ok && n == m
		}
		return false
	}
}

func matchesBound(bound Bound, got reflect.Value) bool {
	n, ok := asFloat(got)
	if !ok {
		return false
	}
	if bound.GteV != nil && n < *bound.GteV {
		return false
	}
	if bound.GtV != nil && n <= *bound.GtV {
		return false
	}
	if bound.LteV != nil && n > *bound.LteV {
		return false
	}
	if bound.LtV != nil && n >= *bound.LtV {
		return false
	}
	return true
}

// Looked up by JSON TAG rather than by field name, so a condition is written in
// the wire's vocabulary - the same one the shared corpus and the API docs use -
// and a Go field rename cannot silently change what a caller may write.
func fieldFor(value reflect.Value, member string) (reflect.Value, bool) {
	if value.Kind() != reflect.Struct {
		return reflect.Value{}, false
	}
	t := value.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Anonymous {
			if found, ok := fieldFor(value.Field(i), member); ok {
				return found, true
			}
			continue
		}
		if tagName(f.Tag.Get("json")) == member {
			return value.Field(i), true
		}
	}
	return reflect.Value{}, false
}

func tagName(tag string) string {
	name, _, _ := strings.Cut(tag, ",")
	return name
}

func isAbsent(v reflect.Value) bool {
	return v.Kind() == reflect.Pointer && v.IsNil()
}

func deref(v reflect.Value) reflect.Value {
	if v.Kind() == reflect.Pointer {
		return v.Elem()
	}
	return v
}

func asFloat(v reflect.Value) (float64, bool) {
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return float64(v.Int()), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return float64(v.Uint()), true
	case reflect.Float32, reflect.Float64:
		return v.Float(), true
	default:
		return 0, false
	}
}
