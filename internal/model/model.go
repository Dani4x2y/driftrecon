// Package model defines the observation documents shared by collectors,
// fingerprinting, storage and reporting.
package model

import "fmt"

// Profile selects how much traffic a scan is allowed to generate.
type Profile string

const (
	// ProfilePassive queries third-party sources only.
	ProfilePassive Profile = "passive"
	// ProfileStandard additionally resolves discovered names and requests
	// the front page of the web services found on them.
	ProfileStandard Profile = "standard"
)

// ParseProfile validates a profile name.
func ParseProfile(s string) (Profile, error) {
	switch p := Profile(s); p {
	case ProfilePassive, ProfileStandard:
		return p, nil
	default:
		return "", fmt.Errorf("unknown profile %q (want %s or %s)", s, ProfilePassive, ProfileStandard)
	}
}

// AssetKind distinguishes the things a target is made of.
type AssetKind string

// KindHost is a DNS name.
const KindHost AssetKind = "host"

// State is the condition an asset was found in during one scan.
type State string

const (
	// StateDiscovered: reported by a source, not resolved in this scan.
	StateDiscovered State = "discovered"
	// StateLive: resolves to at least one address.
	StateLive State = "live"
	// StateUnresolved: the name does not exist or has no address records.
	StateUnresolved State = "unresolved"
	// StateWildcard: resolves, but only to what a wildcard record returns.
	StateWildcard State = "wildcard"
	// StateUnreachable: a service that used to answer no longer does.
	StateUnreachable State = "unreachable"
	// StateError: the asset could not be examined, so nothing is known for
	// this scan.
	StateError State = "error"
)

// HostObservation is what one scan learned about a hostname. Its JSON form is
// stored content-addressed, so slices must be in a deterministic order.
type HostObservation struct {
	Host string `json:"host"`
	DNS  *DNS   `json:"dns,omitempty"`
}

// DNS is the resolution result for a hostname.
type DNS struct {
	Rcode string   `json:"rcode"`
	CNAME []string `json:"cname,omitempty"`
	A     []string `json:"a,omitempty"`
	AAAA  []string `json:"aaaa,omitempty"`
	NS    []string `json:"ns,omitempty"`
}

// ScanStats summarises a finished scan.
type ScanStats struct {
	Hosts    int           `json:"hosts"`
	States   map[State]int `json:"states,omitempty"`
	NewHosts int           `json:"new_hosts"`
	// Services counts the services that were recorded, which leaves out
	// ports where nothing has ever answered.
	Services      int           `json:"services"`
	ServiceStates map[State]int `json:"service_states,omitempty"`
	NewServices   int           `json:"new_services"`
	Sources       []SourceStat  `json:"sources,omitempty"`
	Reason        string        `json:"reason,omitempty"`
}

// SourceStat records how one discovery source performed for one root domain.
type SourceStat struct {
	Source string `json:"source"`
	Domain string `json:"domain"`
	Names  int    `json:"names"`
	Error  string `json:"error,omitempty"`
}
