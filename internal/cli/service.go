package cli

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/Dani4x2y/driftrecon/internal/model"
	"github.com/Dani4x2y/driftrecon/internal/storage"
)

func decodeService(snap storage.AssetSnapshot) (model.ServiceObservation, error) {
	var obs model.ServiceObservation
	if err := json.Unmarshal(snap.Data, &obs); err != nil {
		return obs, fmt.Errorf("asset %s: malformed observation: %w", snap.Key, err)
	}
	return obs, nil
}

func defaultPort(scheme string) uint16 {
	if scheme == "https" {
		return 443
	}
	return 80
}

// displayURL renders a service key the way the service is usually written:
// without the port when it is the default for the scheme.
func displayURL(key string) string {
	if scheme, host, port, ok := model.ParseServiceKey(key); ok && port == defaultPort(scheme) {
		return scheme + "://" + host
	}
	return key
}

// serviceLabel is the short form of a service for the host listing, such as
// "https 200" or "http:8080 down".
func serviceLabel(snap storage.AssetSnapshot, obs model.ServiceObservation) string {
	label := snap.Key
	if scheme, _, port, ok := model.ParseServiceKey(snap.Key); ok {
		label = scheme
		if port != defaultPort(scheme) {
			label += ":" + strconv.Itoa(int(port))
		}
	}

	switch {
	case snap.State == model.StateUnreachable:
		return label + " down"
	case snap.State != model.StateLive:
		return label + " ?"
	case len(obs.Hops) > 0:
		return label + " " + strconv.Itoa(obs.Hops[len(obs.Hops)-1].Status)
	case obs.Error != "":
		return label + " no http"
	}
	return label + " up"
}

// responseSummary condenses how a service answered into one cell: the
// status of every hop, or the reason there is none.
func responseSummary(obs model.ServiceObservation) string {
	if len(obs.Hops) == 0 {
		return obs.Error
	}
	statuses := make([]string, len(obs.Hops))
	for i, hop := range obs.Hops {
		statuses[i] = strconv.Itoa(hop.Status)
	}
	return strings.Join(statuses, " > ")
}

// shorten cuts s to at most limit characters, marking the cut.
func shorten(s string, limit int) string {
	runes := []rune(s)
	if len(runes) <= limit {
		return s
	}
	return string(runes[:limit-3]) + "..."
}

// shortHash is the leading part of a hex digest, enough to tell two apart
// by eye.
func shortHash(digest string) string {
	if len(digest) <= 12 {
		return digest
	}
	return digest[:12]
}
