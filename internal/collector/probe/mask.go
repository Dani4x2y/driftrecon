package probe

import (
	"regexp"
	"strings"
)

var uuidPattern = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

// maskIDs replaces the parts of s that look machine-generated with "*", so
// that a session id, a cache node name or a content hash does not make two
// otherwise equal values differ. With numbers set, plain numbers are masked
// as well: they are identifiers in a path (/orders/1042) but carry meaning
// in a product banner (nginx/1.24.0).
//
// This is a heuristic. Whatever it misses is still caught when it differs
// between two samples of the same scan.
func maskIDs(s string, numbers bool) string {
	s = uuidPattern.ReplaceAllString(s, "*")

	var b strings.Builder
	start := -1
	flush := func(end int) {
		if start < 0 {
			return
		}
		if token := s[start:end]; generated(token, numbers) {
			b.WriteByte('*')
		} else {
			b.WriteString(token)
		}
		start = -1
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			if start < 0 {
				start = i
			}
			continue
		}
		flush(i)
		b.WriteByte(c)
	}
	flush(len(s))
	return b.String()
}

// generated reports whether an alphanumeric token looks like an identifier
// rather than a word or a version.
func generated(token string, numbers bool) bool {
	digits, hex := 0, true
	for i := 0; i < len(token); i++ {
		switch c := token[i]; {
		case c >= '0' && c <= '9':
			digits++
		case c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F':
		default:
			hex = false
		}
	}
	switch {
	case digits == len(token):
		return numbers
	case digits == 0:
		return false
	case hex && len(token) >= 8:
		return true
	default:
		return len(token) >= 20
	}
}
