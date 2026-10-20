// SPDX-License-Identifier: AGPL-3.0-only

package wtp

import (
	"bytes"
	"strconv"
	"unicode/utf8"
)

// MaxSafeInt is 2^53 − 1.
const MaxSafeInt int64 = 9007199254740991

// Limits bounds strict parsing.
type Limits struct {
	MaxBytes         int  // default 1 MiB
	MaxDepth         int  // default 40
	AllowUnicodeKeys bool // only for JCS test vectors; never for envelopes
}

// DefaultLimits are the WTP defaults.
var DefaultLimits = Limits{MaxBytes: 1 << 20, MaxDepth: 40}

// Parse strictly parses application/wtp+json with DefaultLimits.
func Parse(input []byte) (any, error) { return ParseWith(input, DefaultLimits) }

// ParseWith strictly parses JSON: no BOM, no duplicate keys, integers only within
// ±(2^53−1), no leading zeros, no lone surrogates, printable-ASCII member names,
// bounded depth and size, no trailing data.
func ParseWith(input []byte, l Limits) (any, error) {
	if len(input) > l.MaxBytes {
		return nil, errf(ErrSchema, "size exceeded")
	}
	if !utf8.Valid(input) {
		return nil, errf(ErrSchema, "invalid UTF-8")
	}
	if bytes.HasPrefix(input, []byte("\xef\xbb\xbf")) {
		return nil, errf(ErrSchema, "BOM not allowed")
	}
	p := &parser{s: input, l: l}
	p.ws()
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.i != len(p.s) {
		return nil, errf(ErrSchema, "trailing data")
	}
	return v, nil
}

// IsASCIIMemberName reports whether k is non-empty printable ASCII (0x21–0x7E).
func IsASCIIMemberName(k string) bool {
	if k == "" {
		return false
	}
	for i := 0; i < len(k); i++ {
		if k[i] < 0x21 || k[i] > 0x7e {
			return false
		}
	}
	return true
}

type parser struct {
	s []byte
	i int
	l Limits
}

func (p *parser) ws() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t' || p.s[p.i] == '\n' || p.s[p.i] == '\r') {
		p.i++
	}
}

func (p *parser) peek() int {
	if p.i < len(p.s) {
		return int(p.s[p.i])
	}
	return -1
}

func (p *parser) expect(c byte) error {
	if p.peek() == int(c) {
		p.i++
		return nil
	}
	return errf(ErrSchema, "expected %q at byte %d", c, p.i)
}

func (p *parser) lit(word string, v any) (any, error) {
	if bytes.HasPrefix(p.s[p.i:], []byte(word)) {
		p.i += len(word)
		return v, nil
	}
	return nil, errf(ErrSchema, "invalid literal at byte %d", p.i)
}

func (p *parser) value(depth int) (any, error) {
	if depth > p.l.MaxDepth {
		return nil, errf(ErrSchema, "nesting limit")
	}
	switch c := p.peek(); {
	case c == '{':
		return p.object(depth)
	case c == '[':
		return p.array(depth)
	case c == '"':
		return p.str()
	case c == 't':
		return p.lit("true", true)
	case c == 'f':
		return p.lit("false", false)
	case c == 'n':
		return p.lit("null", nil)
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	case c < 0:
		return nil, errf(ErrSchema, "unexpected end of input")
	default:
		return nil, errf(ErrSchema, "unexpected token at byte %d (non-finite numbers are not JSON)", p.i)
	}
}

func (p *parser) object(depth int) (any, error) {
	if err := p.expect('{'); err != nil {
		return nil, err
	}
	m := map[string]any{}
	p.ws()
	if p.peek() == '}' {
		p.i++
		return m, nil
	}
	for {
		p.ws()
		if p.peek() != '"' {
			return nil, errf(ErrSchema, "member name must be a string")
		}
		k, err := p.str()
		if err != nil {
			return nil, err
		}
		if !p.l.AllowUnicodeKeys && !IsASCIIMemberName(k) {
			return nil, errf(ErrSchema, "non-ASCII or empty member name")
		}
		p.ws()
		if err := p.expect(':'); err != nil {
			return nil, err
		}
		p.ws()
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		if _, dup := m[k]; dup {
			return nil, errf(ErrSchema, "duplicate key %q", k)
		}
		m[k] = v
		p.ws()
		switch p.peek() {
		case ',':
			p.i++
		case '}':
			p.i++
			return m, nil
		default:
			return nil, errf(ErrSchema, "expected ',' or '}'")
		}
	}
}

func (p *parser) array(depth int) (any, error) {
	if err := p.expect('['); err != nil {
		return nil, err
	}
	a := []any{}
	p.ws()
	if p.peek() == ']' {
		p.i++
		return a, nil
	}
	for {
		p.ws()
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		a = append(a, v)
		p.ws()
		switch p.peek() {
		case ',':
			p.i++
		case ']':
			p.i++
			return a, nil
		default:
			return nil, errf(ErrSchema, "expected ',' or ']'")
		}
	}
}

func (p *parser) number() (any, error) {
	start := p.i
	if p.peek() == '-' {
		p.i++
	}
	ds := p.i
	for c := p.peek(); c >= '0' && c <= '9'; c = p.peek() {
		p.i++
	}
	digits := p.s[ds:p.i]
	if len(digits) == 0 {
		return nil, errf(ErrSchema, "invalid number")
	}
	if len(digits) > 1 && digits[0] == '0' {
		return nil, errf(ErrSchema, "leading zeros are not allowed")
	}
	if c := p.peek(); c == '.' || c == 'e' || c == 'E' {
		return nil, errf(ErrSchema, "floating numbers not supported by wtp/0.1 JSON profile")
	}
	if len(digits) > 16 {
		return nil, errf(ErrSchema, "unsafe integer")
	}
	n, err := strconv.ParseInt(string(p.s[start:p.i]), 10, 64)
	if err != nil || n > MaxSafeInt || n < -MaxSafeInt {
		return nil, errf(ErrSchema, "unsafe integer")
	}
	return n, nil
}

func (p *parser) hex4() (rune, error) {
	if p.i+4 > len(p.s) {
		return 0, errf(ErrSchema, "truncated \\u escape")
	}
	v, err := strconv.ParseUint(string(p.s[p.i:p.i+4]), 16, 32)
	if err != nil {
		return 0, errf(ErrSchema, "bad \\u escape")
	}
	p.i += 4
	return rune(v), nil
}

func (p *parser) str() (string, error) {
	if err := p.expect('"'); err != nil {
		return "", err
	}
	var out []byte
	for {
		run := p.i
		for p.i < len(p.s) && p.s[p.i] != '"' && p.s[p.i] != '\\' && p.s[p.i] >= 0x20 {
			p.i++
		}
		out = append(out, p.s[run:p.i]...)
		switch c := p.peek(); {
		case c == '"':
			p.i++
			return string(out), nil
		case c == '\\':
			p.i++
			e := p.peek()
			if e < 0 {
				return "", errf(ErrSchema, "truncated escape")
			}
			p.i++
			switch e {
			case '"', '\\', '/':
				out = append(out, byte(e))
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'u':
				hi, err := p.hex4()
				if err != nil {
					return "", err
				}
				cp := hi
				if hi >= 0xD800 && hi < 0xDC00 {
					if !bytes.HasPrefix(p.s[p.i:], []byte(`\u`)) {
						return "", errf(ErrSchema, "unpaired surrogate")
					}
					p.i += 2
					lo, err := p.hex4()
					if err != nil {
						return "", err
					}
					if lo < 0xDC00 || lo >= 0xE000 {
						return "", errf(ErrSchema, "unpaired surrogate")
					}
					cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
				} else if hi >= 0xDC00 && hi < 0xE000 {
					return "", errf(ErrSchema, "unpaired surrogate")
				}
				out = utf8.AppendRune(out, cp)
			default:
				return "", errf(ErrSchema, "invalid escape")
			}
		case c < 0:
			return "", errf(ErrSchema, "unterminated string")
		default:
			return "", errf(ErrSchema, "unescaped control character in string")
		}
	}
}
