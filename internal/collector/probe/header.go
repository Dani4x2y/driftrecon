package probe

import (
	"regexp"
	"slices"
	"strings"

	"github.com/Dani4x2y/driftrecon/internal/model"
)

// tracked lists the headers whose values are recorded: those that name the
// server stack and those that set a security policy. Of every other header
// only the presence and position count.
var tracked = []string{
	"server",
	"via",
	"x-powered-by",
	"x-aspnet-version",
	"x-aspnetmvc-version",
	"x-generator",
	"strict-transport-security",
	"content-security-policy",
	"content-security-policy-report-only",
	"x-frame-options",
	"x-content-type-options",
	"x-xss-protection",
	"referrer-policy",
	"permissions-policy",
	"cross-origin-opener-policy",
	"cross-origin-embedder-policy",
	"cross-origin-resource-policy",
	"access-control-allow-origin",
	"access-control-allow-credentials",
	"www-authenticate",
}

var (
	noncePattern     = regexp.MustCompile(`'nonce-[^']*'`)
	challengePattern = regexp.MustCompile(`(?i)\b(nonce|opaque)="[^"]*"`)
)

// summarizeHeaders reduces a header block to what identifies the server
// behind it.
func summarizeHeaders(x *exchange) *model.Headers {
	h := &model.Headers{}

	seen := make(map[string]bool)
	for _, f := range x.fields {
		// Age is only sent for responses served from a cache, so whether it
		// is there says nothing about the server.
		if seen[f.name] || strings.EqualFold(f.name, "Age") {
			continue
		}
		seen[f.name] = true
		h.Names = append(h.Names, f.name)
	}

	for _, name := range tracked {
		values := x.header.Values(name)
		if len(values) == 0 {
			continue
		}
		if h.Values == nil {
			h.Values = make(map[string]string)
		}
		h.Values[name] = normalizeValue(name, strings.Join(values, ", "))
	}

	h.Cookies = cookies(x.header.Values("Set-Cookie"))
	return h
}

func normalizeValue(name, value string) string {
	value = strings.Join(strings.Fields(value), " ")
	switch name {
	case "content-security-policy", "content-security-policy-report-only":
		return noncePattern.ReplaceAllString(value, "'nonce-*'")
	case "www-authenticate":
		return challengePattern.ReplaceAllString(value, `$1="*"`)
	case "server", "via", "x-powered-by", "x-generator":
		return maskIDs(value, false)
	}
	return value
}

// cookies lists the cookies a response sets by name and security
// attributes. Values are dropped: they are secrets of the session the probe
// was handed, and they differ on every request anyway.
func cookies(lines []string) []model.Cookie {
	var out []model.Cookie
	seen := make(map[string]bool)
	for _, line := range lines {
		parts := strings.Split(line, ";")
		name, _, ok := strings.Cut(parts[0], "=")
		name = maskIDs(strings.TrimSpace(name), false)
		if !ok || name == "" || seen[name] {
			continue
		}
		seen[name] = true

		var flags []string
		for _, attr := range parts[1:] {
			key, value, _ := strings.Cut(attr, "=")
			switch key = strings.ToLower(strings.TrimSpace(key)); key {
			case "secure", "httponly", "partitioned":
				flags = append(flags, key)
			case "samesite":
				flags = append(flags, key+"="+strings.ToLower(strings.TrimSpace(value)))
			}
		}
		slices.Sort(flags)
		out = append(out, model.Cookie{Name: name, Flags: slices.Compact(flags)})
	}
	return out
}
