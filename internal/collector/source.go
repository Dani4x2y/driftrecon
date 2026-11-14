// Package collector defines the contract between the scan engine and the
// components that gather data.
package collector

import "context"

// Source enumerates hostnames a third party knows for a domain. A source
// must not send traffic to the target itself.
type Source interface {
	// Name identifies the source in provenance records and logs.
	Name() string

	// Enumerate returns candidate names for domain exactly as the source
	// reports them: they may be out of scope, wildcards, or not hostnames
	// at all. A non-nil error can come with partial results.
	Enumerate(ctx context.Context, domain string) ([]string, error)
}
