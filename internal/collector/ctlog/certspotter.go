package ctlog

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

const certSpotterURL = "https://api.certspotter.com/v1/issuances"

// maxPages bounds pagination so that one unexpectedly large domain cannot
// spend the whole request quota of the account.
const maxPages = 50

// CertSpotter queries the Cert Spotter issuance API. It works without a
// token at a low rate limit.
type CertSpotter struct {
	c     *client
	url   string
	token string
}

// NewCertSpotter returns a source backed by Cert Spotter.
func NewCertSpotter(o Options) *CertSpotter {
	return &CertSpotter{c: newClient(o), url: cmp.Or(o.BaseURL, certSpotterURL), token: o.Token}
}

// Name implements collector.Source.
func (s *CertSpotter) Name() string {
	return "certspotter"
}

type issuance struct {
	ID       string   `json:"id"`
	DNSNames []string `json:"dns_names"`
}

// Enumerate implements collector.Source.
func (s *CertSpotter) Enumerate(ctx context.Context, domain string) ([]string, error) {
	var header http.Header
	if s.token != "" {
		header = http.Header{"Authorization": {"Bearer " + s.token}}
	}

	names := nameSet{}
	after := ""
	for range maxPages {
		query := url.Values{
			"domain":             {domain},
			"include_subdomains": {"true"},
			"expand":             {"dns_names"},
		}
		if after != "" {
			query.Set("after", after)
		}

		page, err := s.page(ctx, query, header)
		if err != nil {
			return names.sorted(), fmt.Errorf("certspotter: %w", err)
		}
		if len(page) == 0 {
			return names.sorted(), nil
		}
		for _, iss := range page {
			for _, name := range iss.DNSNames {
				names.add(name)
			}
		}
		after = page[len(page)-1].ID
	}
	return names.sorted(), fmt.Errorf("certspotter: stopped after %d pages, results are incomplete", maxPages)
}

func (s *CertSpotter) page(ctx context.Context, query url.Values, header http.Header) ([]issuance, error) {
	resp, err := s.c.get(ctx, s.url+"?"+query.Encode(), header)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var page []issuance
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&page); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return page, nil
}
