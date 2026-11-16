package model

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// KindService is an HTTP endpoint: one scheme, host and port.
const KindService AssetKind = "service"

// ServiceKey builds the asset key of a service. The port is always spelled
// out, so that a key names exactly one endpoint.
func ServiceKey(scheme, host string, port uint16) string {
	return fmt.Sprintf("%s://%s:%d", scheme, host, port)
}

// ParseServiceKey splits a key built by ServiceKey.
func ParseServiceKey(key string) (scheme, host string, port uint16, ok bool) {
	scheme, rest, found := strings.Cut(key, "://")
	i := strings.LastIndexByte(rest, ':')
	if !found || scheme == "" || i <= 0 {
		return "", "", 0, false
	}
	n, err := strconv.ParseUint(rest[i+1:], 10, 16)
	if err != nil {
		return "", "", 0, false
	}
	return scheme, rest[:i], uint16(n), true
}

// ServiceObservation is what one scan learned about an HTTP service. Its
// JSON form is stored content-addressed, so it only holds features that were
// identical in every sample taken during the scan. Whatever differed between
// samples is left out and named in Volatile instead.
type ServiceObservation struct {
	URL string `json:"url"`
	// Error says why nothing else is recorded. It is one of a few fixed
	// phrases, not a raw error message.
	Error string `json:"error,omitempty"`
	TLS   *TLS   `json:"tls,omitempty"`
	// Hops are the responses received while following redirects that stay
	// on this service, ending with the first response that is not such a
	// redirect.
	Hops []Hop `json:"hops,omitempty"`
	// Headers and Page describe the last hop.
	Headers  *Headers `json:"headers,omitempty"`
	Page     *Page    `json:"page,omitempty"`
	Favicon  *int32   `json:"favicon_mmh3,omitempty"`
	Volatile []string `json:"volatile,omitempty"`
}

// TLS is the outcome of a handshake.
type TLS struct {
	Version string `json:"version"`
	Cipher  string `json:"cipher"`
	ALPN    string `json:"alpn,omitempty"`
	// Chain holds the SHA-256 of every certificate the server presented,
	// leaf first.
	Chain []string `json:"chain,omitempty"`
	// Issues lists trust problems that do not depend on the current time.
	// Expiry is derived from the certificate dates when a report is made.
	Issues []string `json:"issues,omitempty"`
}

// Trust problems reported in TLS.Issues.
const (
	IssueSelfSigned       = "self_signed"
	IssueUntrusted        = "untrusted"
	IssueHostnameMismatch = "hostname_mismatch"
)

// Relation places a redirect target relative to the service that issued it.
type Relation string

const (
	// RelSameOrigin: same scheme, host and port. Only these are followed.
	RelSameOrigin Relation = "same-origin"
	// RelSameHost: same host on another scheme or port, such as an upgrade
	// from http to https.
	RelSameHost Relation = "same-host"
	// RelInScope: another host of the target.
	RelInScope Relation = "in-scope"
	// RelExternal: a host outside the scope of the target.
	RelExternal Relation = "external"
)

// Hop is one response in a redirect chain.
type Hop struct {
	Status int `json:"status"`
	// Location is the redirect target with identifiers and query values
	// masked. It is empty for a response that does not redirect.
	Location string   `json:"location,omitempty"`
	Relation Relation `json:"relation,omitempty"`
}

// Headers summarises the header block of a response.
type Headers struct {
	// Names are the header names as the server spelled them, in the order
	// they were sent, each listed once. They are sorted instead when the
	// order itself turned out to be volatile.
	Names []string `json:"names,omitempty"`
	// Values holds the normalised values of the headers that identify the
	// server stack or define a security policy, keyed by lower-case name.
	Values  map[string]string `json:"values,omitempty"`
	Cookies []Cookie          `json:"cookies,omitempty"`
}

// Cookie is a cookie the server tried to set. Values are never recorded.
type Cookie struct {
	Name  string   `json:"name"`
	Flags []string `json:"flags,omitempty"`
}

// Page describes a response body.
type Page struct {
	ContentType string `json:"content_type,omitempty"`
	Title       string `json:"title,omitempty"`
	Generator   string `json:"generator,omitempty"`
	// Skeleton and SimHash are set for HTML documents only.
	Skeleton string   `json:"skeleton,omitempty"`
	SimHash  *SimHash `json:"simhash,omitempty"`
	Forms    []Form   `json:"forms,omitempty"`
	// Scripts are the external scripts the document loads, in document
	// order.
	Scripts    []string `json:"scripts,omitempty"`
	BodySHA256 string   `json:"body_sha256,omitempty"`
	// Truncated marks a body that exceeded the size limit. Everything else
	// was derived from the part that was read.
	Truncated bool `json:"truncated,omitempty"`
}

// Form is the signature of an HTML form.
type Form struct {
	Method string      `json:"method"`
	Action string      `json:"action,omitempty"`
	Fields []FormField `json:"fields,omitempty"`
}

// FormField is one control of a form.
type FormField struct {
	Type string `json:"type"`
	Name string `json:"name,omitempty"`
}

// HasPassword reports whether the form asks for a password.
func (f Form) HasPassword() bool {
	for _, field := range f.Fields {
		if field.Type == "password" {
			return true
		}
	}
	return false
}

// SimHash is a 64-bit locality-sensitive hash. It is written as hex text,
// because JSON numbers cannot carry 64 bits reliably.
type SimHash uint64

func (h SimHash) String() string {
	return fmt.Sprintf("%016x", uint64(h))
}

// MarshalText implements encoding.TextMarshaler.
func (h SimHash) MarshalText() ([]byte, error) {
	return []byte(h.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (h *SimHash) UnmarshalText(text []byte) error {
	v, err := strconv.ParseUint(string(text), 16, 64)
	if err != nil {
		return fmt.Errorf("malformed simhash %q", text)
	}
	*h = SimHash(v)
	return nil
}

// Certificate is the part of an X.509 certificate that drift detection and
// reports work with.
type Certificate struct {
	SHA256     string    `json:"sha256"`
	SubjectCN  string    `json:"subject_cn,omitempty"`
	IssuerCN   string    `json:"issuer_cn,omitempty"`
	IssuerOrg  string    `json:"issuer_org,omitempty"`
	Serial     string    `json:"serial"`
	SANs       []string  `json:"sans,omitempty"`
	SPKISHA256 string    `json:"spki_sha256"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	KeyAlg     string    `json:"key_alg"`
	IsCA       bool      `json:"is_ca,omitempty"`
	SelfSigned bool      `json:"self_signed,omitempty"`
}
