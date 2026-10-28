package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxWireBytes and MaxWireDepth bound parsing and canonicalization, including
// caller-supplied encoded messages. Root depth is zero.
const MaxWireBytes = 1_000_000
const MaxWireDepth = 128

var errCanonical = errors.New("invalid canonical host JSON")

// checkWireBudget bounds input before any recursive decoder or validator runs.
func checkWireBudget(data []byte) error {
	if len(data) > MaxWireBytes {
		return errors.New("host JSON exceeds byte limit")
	}
	depth := 0
	quoted, escaped := false, false
	for _, c := range data {
		if quoted {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				quoted = false
			}
			continue
		}
		switch c {
		case '"':
			quoted = true
		case '{', '[':
			// An object/array at the root has depth zero.
			if depth > MaxWireDepth {
				return errors.New("host JSON exceeds depth limit")
			}
			depth++
		case '}', ']':
			depth--
		}
	}
	return nil
}

func parseCanonical(data []byte) (any, error) {
	if err := checkWireBudget(data); err != nil {
		return nil, err
	}
	if err := validateJSONUnicode(data); err != nil {
		return nil, err
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value any
	if err := d.Decode(&value); err != nil {
		return nil, errCanonical
	}
	return value, nil
}

// CanonicalizeJSON implements neticora-json-v1 on original JSON bytes, preserving
// exact decimal strings and Unicode. It does not validate a message schema or
// establish identity, authorization, hash agreement or durable acceptance.
func CanonicalizeJSON(data []byte) ([]byte, error) {
	value, err := parseCanonical(data)
	if err != nil {
		return nil, err
	}
	return canonicalValue(value)
}

// LogicalHashJSON returns the SHA-256 of canonical bytes. It excludes no fields;
// use PayloadHashJSON for a protocol message with a defined self-hash field.
func LogicalHashJSON(data []byte) (string, error) {
	canonical, err := CanonicalizeJSON(data)
	if err != nil {
		return "", err
	}
	return hashBytes(canonical), nil
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func canonicalValue(value any) ([]byte, error) {
	var b bytes.Buffer
	var appendValue func(any, int) error
	write := func(s string) error {
		if len(s) > MaxWireBytes-b.Len() {
			return errors.New("canonical host JSON exceeds byte limit")
		}
		b.WriteString(s)
		return nil
	}
	var quote func(string) error
	quote = func(s string) error {
		if !utf8.ValidString(s) {
			return errCanonical
		}
		if err := write("\""); err != nil {
			return err
		}
		for _, c := range s {
			var part string
			switch c {
			case '"':
				part = `\"`
			case '\\':
				part = `\\`
			case '\b':
				part = `\b`
			case '\f':
				part = `\f`
			case '\n':
				part = `\n`
			case '\r':
				part = `\r`
			case '\t':
				part = `\t`
			default:
				if c < 0x20 {
					part = `\u00` + string("0123456789abcdef"[byte(c)>>4]) + string("0123456789abcdef"[byte(c)&15])
				} else {
					part = string(c)
				}
			}
			if err := write(part); err != nil {
				return err
			}
		}
		return write("\"")
	}
	appendValue = func(v any, depth int) error {
		if depth > MaxWireDepth {
			return errors.New("canonical host JSON exceeds depth limit")
		}
		switch x := v.(type) {
		case nil:
			return write("null")
		case bool:
			return write(strconv.FormatBool(x))
		case string:
			return quote(x)
		case json.Number:
			n, err := canonicalNumber(string(x))
			if err != nil {
				return err
			}
			return write(n)
		case []any:
			if err := write("["); err != nil {
				return err
			}
			for i, child := range x {
				if i > 0 {
					if err := write(","); err != nil {
						return err
					}
				}
				if err := appendValue(child, depth+1); err != nil {
					return err
				}
			}
			return write("]")
		case map[string]any:
			keys := make([]string, 0, len(x))
			for key := range x {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			if err := write("{"); err != nil {
				return err
			}
			for i, key := range keys {
				if i > 0 {
					if err := write(","); err != nil {
						return err
					}
				}
				if err := quote(key); err != nil {
					return err
				}
				if err := write(":"); err != nil {
					return err
				}
				if err := appendValue(x[key], depth+1); err != nil {
					return err
				}
			}
			return write("}")
		default:
			return errCanonical
		}
	}
	if err := appendValue(value, 0); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Work on decimal text rather than floats or exponent-sized big integers.
func canonicalNumber(raw string) (string, error) {
	negative := strings.HasPrefix(raw, "-")
	raw = strings.TrimPrefix(raw, "-")
	mantissa, exponent, hasExponent := strings.Cut(strings.ToLower(raw), "e")
	whole, fraction, _ := strings.Cut(mantissa, ".")
	digits := strings.TrimLeft(whole+fraction, "0")
	if digits == "" {
		return "0", nil
	}
	exp := 0
	if hasExponent {
		parsed, err := strconv.Atoi(exponent)
		// A nonzero safe integer needs an exponent within the input digit budget.
		if err != nil || parsed > MaxWireBytes || parsed < -MaxWireBytes {
			return "", errCanonical
		}
		exp = parsed
	}
	shift := exp - len(fraction)
	if shift < 0 {
		cut := -shift
		if cut >= len(digits) || strings.Trim(digits[len(digits)-cut:], "0") != "" {
			return "", errCanonical
		}
		digits = digits[:len(digits)-cut]
	} else {
		if len(digits)+shift > 16 {
			return "", errCanonical
		}
		digits += strings.Repeat("0", shift)
	}
	if len(digits) > 16 || (len(digits) == 16 && digits > "9007199254740991") {
		return "", errCanonical
	}
	if negative {
		digits = "-" + digits
	}
	return digits, nil
}

func hashField(schema string) (string, error) {
	switch schema {
	case "ExecutionSpec":
		return "specHash", nil
	case "HostCommand", "StartCommand", "ControlCommand", "HostEvent":
		return "payloadHash", nil
	default:
		return "", errors.New("schema has no defined logical self-hash")
	}
}

// PayloadHashJSON validates the message shape then hashes the canonical object
// excluding exactly its defined top-level self-hash field. The supplied hash may
// be a placeholder. Encoding for transmission still requires EncodeValidatedJSON.
func PayloadHashJSON(schema string, data []byte) (string, error) {
	field, err := hashField(schema)
	if err != nil {
		return "", err
	}
	if err = Validate(schema, data); err != nil {
		return "", err
	}
	value, err := parseCanonical(data)
	if err != nil {
		return "", err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return "", errCanonical
	}
	delete(object, field)
	canonical, err := canonicalValue(object)
	if err != nil {
		return "", err
	}
	return hashBytes(canonical), nil
}

// Outbound is a detached validated snapshot. Byte access returns a copy, so
// subsequent caller mutation cannot alter the bytes checked for transmission.
// An Outbound value is not an authentication or durability proof.
type Outbound struct{ data []byte }

func (m Outbound) Bytes() []byte { return bytes.Clone(m.data) }
func (m Outbound) WriteTo(w io.Writer) (int64, error) {
	if len(m.data) == 0 {
		return 0, errors.New("uninitialized outbound message")
	}
	n, err := w.Write(bytes.Clone(m.data))
	if err == nil && n != len(m.data) {
		err = io.ErrShortWrite
	}
	return int64(n), err
}

// EncodeValidatedJSON validates and canonicalizes a snapshot of the completed
// original message. Defined self-hashes (including nested execution specs) must
// match. No missing fields are supplied and stale hashes are never repaired.
func EncodeValidatedJSON(schema string, data []byte) (Outbound, error) {
	value, err := validatedMessageSnapshot(schema, data)
	if err != nil {
		return Outbound{}, err
	}
	canonical, err := canonicalValue(value)
	if err != nil {
		return Outbound{}, err
	}
	return Outbound{data: canonical}, nil
}

// ValidateInboundJSON checks schema and all defined logical self-hashes before
// an incoming message is used. It rejects stale nested ExecutionSpec and event
// hashes as well. It does not authenticate the sender, authorize a command or
// establish durable acceptance. Validate alone intentionally checks shape only.
func ValidateInboundJSON(schema string, data []byte) error {
	_, err := validatedMessageSnapshot(schema, data)
	return err
}

func validatedMessageSnapshot(schema string, data []byte) (any, error) {
	if len(data) > MaxWireBytes {
		return nil, errors.New("host JSON exceeds byte limit")
	}
	data = bytes.Clone(data)
	if err := Validate(schema, data); err != nil {
		return nil, err
	}
	value, err := parseCanonical(data)
	if err != nil {
		return nil, err
	}
	if err = verifyMessageHash(schema, value); err != nil {
		return nil, err
	}
	return value, nil
}

func verifyMessageHash(schema string, value any) error {
	if schema == "EventBatch" {
		for _, event := range value.(map[string]any)["events"].([]any) {
			if err := verifyMessageHash("HostEvent", event); err != nil {
				return err
			}
		}
		return nil
	}
	field, err := hashField(schema)
	if err != nil {
		return nil
	} // Non-hashed schemas still validate.
	object, ok := value.(map[string]any)
	if !ok {
		return errCanonical
	}
	supplied := object[field]
	payload := make(map[string]any, len(object))
	for key, child := range object {
		if key != field {
			payload[key] = child
		}
	}
	canonical, err := canonicalValue(payload)
	if err != nil {
		return err
	}
	if supplied != hashBytes(canonical) {
		return errors.New("host protocol logical hash mismatch")
	}
	if spec, ok := object["spec"]; ok {
		return verifyMessageHash("ExecutionSpec", spec)
	}
	return nil
}

// EncodeValidated snapshots generated/native values before validated encoding.
// Concurrent mutation by the caller is unsupported. Invalid native Unicode is
// rejected before encoding/json could replace it. Prefer EncodeValidatedJSON
// when the original bytes are available.
func EncodeValidated(schema string, value any) (Outbound, error) {
	if err := checkNative(reflect.ValueOf(value), 0); err != nil {
		return Outbound{}, err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return Outbound{}, errors.New("host protocol encoding failed")
	}
	return EncodeValidatedJSON(schema, data)
}

func checkNative(v reflect.Value, depth int) error {
	if depth > MaxWireDepth {
		return errors.New("native host value exceeds depth limit")
	}
	for refs := 0; v.IsValid() && (v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer); refs++ {
		if refs > MaxWireDepth {
			return errors.New("cyclic native host value")
		}
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}
	if !v.IsValid() {
		return nil
	}
	if (v.Kind() == reflect.String || v.Kind() == reflect.Map || v.Kind() == reflect.Array || v.Kind() == reflect.Slice) && v.Len() > MaxWireBytes {
		return errors.New("native host value exceeds size limit")
	}
	switch v.Kind() {
	case reflect.String:
		if !utf8.ValidString(v.String()) {
			return errors.New("invalid native host Unicode")
		}
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			if err := checkNative(iter.Key(), depth+1); err != nil {
				return err
			}
			if err := checkNative(iter.Value(), depth+1); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if err := checkNative(v.Index(i), depth+1); err != nil {
				return err
			}
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				if err := checkNative(v.Field(i), depth+1); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
