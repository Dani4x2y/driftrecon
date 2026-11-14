package ctlog

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
)

const crtshURL = "https://crt.sh/"

// CrtSh queries the crt.sh certificate search.
type CrtSh struct {
	c   *client
	url string
}

// NewCrtSh returns a source backed by crt.sh.
func NewCrtSh(o Options) *CrtSh {
	return &CrtSh{c: newClient(o), url: cmp.Or(o.BaseURL, crtshURL)}
}

// Name implements collector.Source.
func (s *CrtSh) Name() string {
	return "crtsh"
}

// Enumerate implements collector.Source.
func (s *CrtSh) Enumerate(ctx context.Context, domain string) ([]string, error) {
	query := url.Values{"q": {"%." + domain}, "output": {"json"}}
	resp, err := s.c.get(ctx, s.url+"?"+query.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("crtsh: %w", err)
	}
	defer resp.Body.Close()

	// The answer is one large array. Decoding it element by element keeps
	// memory proportional to the number of distinct names.
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
		return nil, errors.New("crtsh: response is not a JSON array")
	}

	names := nameSet{}
	for dec.More() {
		var entry struct {
			CommonName string `json:"common_name"`
			NameValue  string `json:"name_value"`
		}
		if err := dec.Decode(&entry); err != nil {
			return names.sorted(), fmt.Errorf("crtsh: truncated response: %w", err)
		}
		names.add(entry.CommonName)
		for name := range strings.SplitSeq(entry.NameValue, "\n") {
			names.add(name)
		}
	}
	return names.sorted(), nil
}
