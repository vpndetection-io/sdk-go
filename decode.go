package vpndetection

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"time"
)

// Reads the JSON answer a call returns. Anything but a 2xx is classified by its
// status before the body is decoded, so a proxy's HTML 401 is unauthorized and
// sent once. A 2xx that is not the answer - a proxy's HTML page, a cut-off or
// empty body, `null`, or one without a member the answer requires - is a server
// error carrying that status, retried like a 5xx. Through v5.5.2 an HTML page
// was a bad_request sent once, a cut-off body or `[]` a network error with no
// status, `{}` or `null` an answer of zero values, and a JSON 401 the
// generated parser could not decode a retried network error.
func decodeAnswer[T any](res *http.Response, err error) (*T, error) {
	if err != nil {
		return nil, errorFromTransport(err)
	}
	body, err := readBody(res)
	if err != nil {
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, errorFromResponse(res.StatusCode, res.Header, body)
	}
	answer, ok := decodeComplete[T](body)
	if !ok {
		return nil, unreadable(res.StatusCode, "the response was not the answer this call returns")
	}
	return answer, nil
}

// Decodes raw as a T holding every member T requires.
func decodeComplete[T any](raw []byte) (*T, bool) {
	var answer T
	var value any
	if json.Unmarshal(raw, &answer) != nil || json.Unmarshal(raw, &value) != nil ||
		!complete(reflect.TypeFor[T](), value) {
		return nil, false
	}
	return &answer, true
}

var (
	unmarshaler = reflect.TypeFor[json.Unmarshaler]()
	timeType    = reflect.TypeFor[time.Time]()
)

// Reports whether a date-time time.Time has already read ends in a zone RFC
// 3339 allows: Z, or an offset of at most 23 hours and 59 minutes. time.Time
// reads +24:00 and +05:60 too, so through v5.9.0 either was a date a day or an
// hour off.
func rfc3339Offset(value string) bool {
	if strings.HasSuffix(value, "Z") {
		return true
	}
	if len(value) < len("+00:00") {
		return false
	}
	offset := value[len(value)-len("+00:00"):]
	return (offset[0] == '+' || offset[0] == '-') && offset[3] == ':' &&
		offset[1:3] <= "23" && offset[4:6] <= "59"
}

// Reports whether raw, a decoded JSON value, carries every member t requires,
// at every depth. The generated types spell a member the spec requires and does
// not allow to be null as neither a pointer nor omitempty, so that is the rule:
// present, and not null. json.Unmarshal checks neither, and reads a missing or
// null member as its zero value.
func complete(t reflect.Type, raw any) bool {
	if raw == nil {
		return t.Kind() == reflect.Pointer || t.Kind() == reflect.Interface
	}
	if t.Kind() == reflect.Pointer {
		return complete(t.Elem(), raw)
	}
	if t == timeType {
		value, ok := raw.(string)
		return ok && rfc3339Offset(value)
	}
	if reflect.PointerTo(t).Implements(unmarshaler) {
		return true
	}
	switch t.Kind() {
	case reflect.Struct:
		object, ok := raw.(map[string]any)
		if !ok {
			return false
		}
		for i := range t.NumField() {
			field := t.Field(i)
			name, options, _ := strings.Cut(field.Tag.Get("json"), ",")
			if !field.IsExported() || name == "" || name == "-" {
				continue
			}
			value, present := object[name]
			required := field.Type.Kind() != reflect.Pointer && !strings.Contains(options, "omitempty")
			if (required && !present) || (present && !complete(field.Type, value)) {
				return false
			}
		}
	case reflect.Slice:
		items, ok := raw.([]any)
		if !ok {
			return false
		}
		for _, item := range items {
			if !complete(t.Elem(), item) {
				return false
			}
		}
	case reflect.Map:
		entries, ok := raw.(map[string]any)
		if !ok {
			return false
		}
		for _, entry := range entries {
			if !complete(t.Elem(), entry) {
				return false
			}
		}
	}
	return true
}
