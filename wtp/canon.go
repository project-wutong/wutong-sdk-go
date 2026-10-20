// SPDX-License-Identifier: AGPL-3.0-only

package wtp

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf16"
)

// JCS returns the RFC 8785 canonical form of a value from the restricted data model.
func JCS(v any) ([]byte, error) {
	var b []byte
	return jcsAppend(b, v)
}

func utf16Less(a, b string) bool {
	x, y := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return len(x) < len(y)
}

func jcsAppend(b []byte, v any) ([]byte, error) {
	var err error
	switch t := v.(type) {
	case nil:
		return append(b, "null"...), nil
	case bool:
		return strconv.AppendBool(b, t), nil
	case int64:
		if t > MaxSafeInt || t < -MaxSafeInt {
			return nil, errf(ErrSchema, "only safe integers are allowed")
		}
		return strconv.AppendInt(b, t, 10), nil
	case int:
		return jcsAppend(b, int64(t))
	case string:
		return jcsString(b, t), nil
	case []any:
		b = append(b, '[')
		for i, x := range t {
			if i > 0 {
				b = append(b, ',')
			}
			if b, err = jcsAppend(b, x); err != nil {
				return nil, err
			}
		}
		return append(b, ']'), nil
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		b = append(b, '{')
		for i, k := range keys {
			if i > 0 {
				b = append(b, ',')
			}
			b = jcsString(b, k)
			b = append(b, ':')
			if b, err = jcsAppend(b, t[k]); err != nil {
				return nil, err
			}
		}
		return append(b, '}'), nil
	default:
		return nil, errf(ErrSchema, "unsupported type %T", v)
	}
}

func jcsString(b []byte, s string) []byte {
	b = append(b, '"')
	for _, r := range s {
		switch r {
		case '"':
			b = append(b, `\"`...)
		case '\\':
			b = append(b, `\\`...)
		case '\b':
			b = append(b, `\b`...)
		case '\f':
			b = append(b, `\f`...)
		case '\n':
			b = append(b, `\n`...)
		case '\r':
			b = append(b, `\r`...)
		case '\t':
			b = append(b, `\t`...)
		default:
			if r < 0x20 {
				b = append(b, fmt.Sprintf(`\u%04x`, r)...)
			} else {
				b = append(b, string(r)...)
			}
		}
	}
	return append(b, '"')
}

// Canonicalize strictly parses JSON and returns its JCS form.
func Canonicalize(input []byte) ([]byte, error) {
	v, err := Parse(input)
	if err != nil {
		return nil, err
	}
	return JCS(v)
}

// SHA256Digest returns "sha256:<lowercase hex>".
func SHA256Digest(data []byte) string {
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

// DCBOR encodes a value with the WTP deterministic CBOR profile (RFC 8949 §4.2.1:
// shortest heads, definite lengths, no tags/floats/byte strings, map keys sorted by
// their encoded bytes).
func DCBOR(v any) ([]byte, error) { return cborAppend(nil, v) }

func cborHead(b []byte, major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return append(b, m|byte(n))
	case n <= 0xff:
		return append(b, m|24, byte(n))
	case n <= 0xffff:
		return binary.BigEndian.AppendUint16(append(b, m|25), uint16(n))
	case n <= 0xffffffff:
		return binary.BigEndian.AppendUint32(append(b, m|26), uint32(n))
	default:
		return binary.BigEndian.AppendUint64(append(b, m|27), n)
	}
}

func cborAppend(b []byte, v any) ([]byte, error) {
	var err error
	switch t := v.(type) {
	case nil:
		return append(b, 0xf6), nil
	case bool:
		if t {
			return append(b, 0xf5), nil
		}
		return append(b, 0xf4), nil
	case int:
		return cborAppend(b, int64(t))
	case int64:
		if t > MaxSafeInt || t < -MaxSafeInt {
			return nil, errf(ErrSchema, "only safe integers are allowed")
		}
		if t >= 0 {
			return cborHead(b, 0, uint64(t)), nil
		}
		return cborHead(b, 1, uint64(-1-t)), nil
	case string:
		return append(cborHead(b, 3, uint64(len(t))), t...), nil
	case []any:
		b = cborHead(b, 4, uint64(len(t)))
		for _, x := range t {
			if b, err = cborAppend(b, x); err != nil {
				return nil, err
			}
		}
		return b, nil
	case map[string]any:
		type kv struct{ k, v []byte }
		items := make([]kv, 0, len(t))
		for k, x := range t {
			kb, _ := cborAppend(nil, k)
			vb, err := cborAppend(nil, x)
			if err != nil {
				return nil, err
			}
			items = append(items, kv{kb, vb})
		}
		sort.Slice(items, func(i, j int) bool { return string(items[i].k) < string(items[j].k) })
		b = cborHead(b, 5, uint64(len(items)))
		for _, it := range items {
			b = append(append(b, it.k...), it.v...)
		}
		return b, nil
	default:
		return nil, errf(ErrSchema, "unsupported type %T", v)
	}
}
