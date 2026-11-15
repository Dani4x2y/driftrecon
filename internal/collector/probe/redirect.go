package probe

import (
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/Dani4x2y/driftrecon/internal/model"
	"github.com/Dani4x2y/driftrecon/internal/scope"
)

// redirectTarget returns where a redirecting response points, resolved
// against the URL that was requested. It is nil for any other response and
// for a target that cannot be parsed.
func redirectTarget(x *exchange, from *url.URL) *url.URL {
	if !x.redirects() {
		return nil
	}
	u, err := from.Parse(x.header.Get("Location"))
	if err != nil {
		return nil
	}
	u.Fragment = ""
	return u
}

// requestTarget is u as it goes on a request line.
func requestTarget(u *url.URL) string {
	return strings.ReplaceAll(u.RequestURI(), " ", "%20")
}

// relation places u relative to the service. inScope may be nil.
func (o origin) relation(u *url.URL, inScope func(string) bool) model.Relation {
	if u.Scheme != "http" && u.Scheme != "https" {
		return model.RelExternal
	}
	host, err := scope.NormalizeHost(u.Hostname())
	switch {
	case err != nil:
		return model.RelExternal
	case host != o.host:
		if inScope != nil && inScope(host) {
			return model.RelInScope
		}
		return model.RelExternal
	case u.Scheme == o.scheme && portOf(u) == o.port:
		return model.RelSameOrigin
	default:
		return model.RelSameHost
	}
}

func portOf(u *url.URL) uint16 {
	port := u.Port()
	if port == "" {
		return defaultPort(u.Scheme)
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(n)
}

// locationPattern renders a URL for comparison between scans: identifiers
// in the path are masked and of the query only the parameter names remain.
func locationPattern(u *url.URL) string {
	if u.Scheme != "http" && u.Scheme != "https" {
		return u.Scheme + ":"
	}

	var b strings.Builder
	b.WriteString(u.Scheme)
	b.WriteString("://")
	if host := strings.ToLower(u.Hostname()); strings.Contains(host, ":") {
		b.WriteString("[" + host + "]")
	} else {
		b.WriteString(host)
	}
	if port := portOf(u); port != defaultPort(u.Scheme) {
		b.WriteString(":" + strconv.Itoa(int(port)))
	}
	b.WriteString(pathPattern(u.EscapedPath()))
	if keys := queryKeys(u.RawQuery); len(keys) > 0 {
		b.WriteString("?" + strings.Join(keys, "&"))
	}
	return b.String()
}

func pathPattern(path string) string {
	if path == "" {
		return "/"
	}
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		// Path parameters are where servers put session ids when cookies
		// are not available (;jsessionid=...).
		segment, _, _ = strings.Cut(segment, ";")
		segments[i] = maskIDs(segment, true)
	}
	return strings.Join(segments, "/")
}

func queryKeys(query string) []string {
	var keys []string
	for query != "" {
		var pair string
		pair, query, _ = strings.Cut(query, "&")
		if key, _, _ := strings.Cut(pair, "="); key != "" {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	return slices.Compact(keys)
}
