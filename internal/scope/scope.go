// Package scope decides which hostnames belong to a target.
package scope

import (
	"errors"
	"fmt"
	"net/netip"
	"path"
	"slices"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// ErrInvalidHost is returned for names that cannot be a DNS hostname.
var ErrInvalidHost = errors.New("invalid hostname")

// The strict IDNA lookup profile rejects underscores and labels with "--" in
// the third position. Both occur in real zones, so those checks are relaxed
// and the character set is validated separately.
var hostProfile = idna.New(
	idna.MapForLookup(),
	idna.StrictDomainName(false),
	idna.CheckHyphens(false),
)

// Rules is the persisted definition of a target's scope. Include and Exclude
// hold glob patterns in which "*" also matches across labels.
type Rules struct {
	Roots   []string `json:"roots"`
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}

// Scope matches hostnames against a validated set of rules.
type Scope struct {
	rules Rules
}

// New validates r and brings it into canonical form.
func New(r Rules) (*Scope, error) {
	if len(r.Roots) == 0 {
		return nil, errors.New("scope: at least one root domain is required")
	}

	var rules Rules
	for _, root := range r.Roots {
		host, err := NormalizeHost(root)
		if err != nil {
			return nil, fmt.Errorf("scope: root %q: %w", root, err)
		}
		if suffix, _ := publicsuffix.PublicSuffix(host); suffix == host {
			return nil, fmt.Errorf("scope: root %q is a public suffix", root)
		}
		rules.Roots = append(rules.Roots, host)
	}
	slices.Sort(rules.Roots)
	rules.Roots = slices.Compact(rules.Roots)

	var err error
	if rules.Include, err = normalizePatterns(r.Include); err != nil {
		return nil, err
	}
	if rules.Exclude, err = normalizePatterns(r.Exclude); err != nil {
		return nil, err
	}
	return &Scope{rules: rules}, nil
}

// Rules returns the canonical rules, suitable for persisting.
func (s *Scope) Rules() Rules {
	return s.rules
}

// Roots returns the root domains in sorted order.
func (s *Scope) Roots() []string {
	return s.rules.Roots
}

// IsRoot reports whether host is one of the root domains.
func (s *Scope) IsRoot(host string) bool {
	_, found := slices.BinarySearch(s.rules.Roots, host)
	return found
}

// Contains reports whether host, in the form produced by NormalizeHost, is
// covered by the scope.
func (s *Scope) Contains(host string) bool {
	if !s.underRoot(host) || matchAny(s.rules.Exclude, host) {
		return false
	}
	return len(s.rules.Include) == 0 || matchAny(s.rules.Include, host)
}

func (s *Scope) underRoot(host string) bool {
	for _, root := range s.rules.Roots {
		if host == root || strings.HasSuffix(host, "."+root) {
			return true
		}
	}
	return false
}

// NormalizeHost returns the canonical form of a DNS name: punycode, lower
// case, without a trailing dot or a leading wildcard label. Names taken from
// certificates are not guaranteed to be hostnames at all, so anything that is
// not one is rejected.
func NormalizeHost(name string) (string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.TrimSuffix(name, ".")
	name = strings.TrimPrefix(name, "*.")
	if name == "" {
		return "", ErrInvalidHost
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return "", fmt.Errorf("%w: %q is an IP address", ErrInvalidHost, name)
	}

	ascii, err := hostProfile.ToASCII(name)
	if err != nil {
		return "", fmt.Errorf("%w: %q", ErrInvalidHost, name)
	}
	if !validHostname(ascii) {
		return "", fmt.Errorf("%w: %q", ErrInvalidHost, name)
	}
	return ascii, nil
}

func validHostname(name string) bool {
	if len(name) > 253 || !strings.Contains(name, ".") {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := range len(label) {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			default:
				return false
			}
		}
	}
	return true
}

func normalizePatterns(patterns []string) ([]string, error) {
	var out []string
	for _, p := range patterns {
		p = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(p)), ".")
		if p == "" {
			continue
		}
		if _, err := path.Match(p, ""); err != nil {
			return nil, fmt.Errorf("scope: pattern %q: %w", p, err)
		}
		out = append(out, p)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

func matchAny(patterns []string, host string) bool {
	for _, p := range patterns {
		if ok, _ := path.Match(p, host); ok {
			return true
		}
	}
	return false
}
