package cli

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Dani4x2y/driftrecon/internal/model"
	"github.com/Dani4x2y/driftrecon/internal/report"
	"github.com/Dani4x2y/driftrecon/internal/storage"
)

func newAssetsCmd(a *app) *cobra.Command {
	var (
		scanID int64
		kind   string
		states []string
	)
	cmd := &cobra.Command{
		Use:   "assets <target>",
		Short: "List the hosts or services recorded by a scan",
		Long: `List what a scan recorded, by default the hosts of the latest completed
scan. With --kind service the web services found on them are listed instead.

Host states:
  live         resolves to at least one address
  wildcard     resolves only because of a wildcard record
  unresolved   does not exist or has no address records
  discovered   reported by a source, not resolved (passive scans)
  error        the lookup failed, nothing is known for this scan

Service states:
  live         answered
  unreachable  answered in an earlier scan, but not in this one
  error        could not be examined, nothing is known for this scan`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			valid := hostStates
			switch model.AssetKind(kind) {
			case model.KindHost:
			case model.KindService:
				valid = serviceStates
			default:
				return fmt.Errorf("unknown kind %q (want %s or %s)", kind, model.KindHost, model.KindService)
			}
			filter, err := parseStates(states, valid)
			if err != nil {
				return err
			}

			_, store, err := a.open(ctx)
			if err != nil {
				return err
			}
			defer store.Close()

			target, err := store.GetTarget(ctx, args[0])
			if err != nil {
				return err
			}
			scan, err := selectScan(cmd, store, target, scanID)
			if err != nil {
				return err
			}
			snaps, err := store.Snapshots(ctx, scan.ID)
			if err != nil {
				return err
			}

			if model.AssetKind(kind) == model.KindHost {
				return renderHosts(cmd.OutOrStdout(), target, scan, snaps, filter)
			}

			var digests []string
			for _, snap := range snaps {
				if snap.CertSHA256 != "" {
					digests = append(digests, snap.CertSHA256)
				}
			}
			slices.Sort(digests)
			certs, err := store.Certificates(ctx, slices.Compact(digests)...)
			if err != nil {
				return err
			}
			return renderServices(cmd.OutOrStdout(), target, scan, snaps, certs, filter)
		},
	}

	flags := cmd.Flags()
	flags.Int64Var(&scanID, "scan", 0, "scan to show (default: latest completed scan)")
	flags.StringVar(&kind, "kind", string(model.KindHost), "what to list: host or service")
	flags.StringSliceVar(&states, "state", nil, "only show assets in this state (repeatable)")
	return cmd
}

func parseStates(names []string, valid []model.State) (map[model.State]bool, error) {
	filter := make(map[model.State]bool, len(names))
	for _, name := range names {
		state := model.State(strings.ToLower(name))
		if !slices.Contains(valid, state) {
			options := make([]string, len(valid))
			for i, s := range valid {
				options[i] = string(s)
			}
			return nil, fmt.Errorf("unknown state %q (want one of: %s)", name, strings.Join(options, ", "))
		}
		filter[state] = true
	}
	return filter, nil
}

func renderHosts(w io.Writer, target *storage.Target, scan *storage.Scan, snaps []storage.AssetSnapshot, filter map[model.State]bool) error {
	var hosts []storage.AssetSnapshot
	services := make(map[string][]string)
	for _, snap := range snaps {
		if snap.Kind != model.KindService {
			hosts = append(hosts, snap)
			continue
		}
		obs, err := decodeService(snap)
		if err != nil {
			return err
		}
		services[snap.Host] = append(services[snap.Host], serviceLabel(snap, obs))
	}
	slices.SortFunc(hosts, func(a, b storage.AssetSnapshot) int {
		return cmp.Compare(domainKey(a.Host), domainKey(b.Host))
	})

	table := report.Table{Header: []string{"HOST", "STATE", "ADDRESSES", "CNAME", "SERVICES", "SOURCES", "FIRST SEEN"}}
	for _, snap := range hosts {
		if len(filter) > 0 && !filter[snap.State] {
			continue
		}
		var obs model.HostObservation
		if err := json.Unmarshal(snap.Data, &obs); err != nil {
			return fmt.Errorf("asset %s: malformed observation: %w", snap.Key, err)
		}

		var addrs, cname string
		if obs.DNS != nil {
			addrs = abbreviate(slices.Concat(obs.DNS.A, obs.DNS.AAAA), 2)
			if n := len(obs.DNS.CNAME); n > 0 {
				cname = obs.DNS.CNAME[n-1]
			}
		}
		table.Rows = append(table.Rows, []string{
			snap.Host,
			string(snap.State),
			addrs,
			cname,
			strings.Join(services[snap.Host], ", "),
			strings.Join(snap.Sources, ","),
			snap.FirstSeenAt.Format(time.DateOnly),
		})
	}
	return renderListing(w, target, scan, table, len(hosts), "hosts")
}

func renderServices(w io.Writer, target *storage.Target, scan *storage.Scan, snaps []storage.AssetSnapshot, certs map[string]model.Certificate, filter map[model.State]bool) error {
	var services []storage.AssetSnapshot
	for _, snap := range snaps {
		if snap.Kind == model.KindService {
			services = append(services, snap)
		}
	}
	slices.SortFunc(services, func(a, b storage.AssetSnapshot) int {
		return cmp.Or(cmp.Compare(domainKey(a.Host), domainKey(b.Host)), cmp.Compare(a.Key, b.Key))
	})

	table := report.Table{Header: []string{"SERVICE", "STATE", "RESPONSE", "TITLE", "SERVER", "CERT EXPIRES", "FIRST SEEN"}}
	for _, snap := range services {
		if len(filter) > 0 && !filter[snap.State] {
			continue
		}
		obs, err := decodeService(snap)
		if err != nil {
			return err
		}

		var title, server, expires string
		if obs.Page != nil {
			title = shorten(obs.Page.Title, 40)
		}
		if obs.Headers != nil {
			server = shorten(obs.Headers.Values["server"], 30)
		}
		if cert, ok := certs[snap.CertSHA256]; ok {
			expires = cert.NotAfter.Format(time.DateOnly)
		}
		table.Rows = append(table.Rows, []string{
			displayURL(snap.Key),
			string(snap.State),
			responseSummary(obs),
			title,
			server,
			expires,
			snap.FirstSeenAt.Format(time.DateOnly),
		})
	}
	return renderListing(w, target, scan, table, len(services), "services")
}

// renderListing prints the header line of a listing followed by its table.
func renderListing(w io.Writer, target *storage.Target, scan *storage.Scan, table report.Table, total int, noun string) error {
	_, err := fmt.Fprintf(w, "scan #%d of %s (%s, %s): %d of %d %s\n",
		scan.ID, target.Name, scan.Profile, scan.StartedAt.Format(timeFormat), len(table.Rows), total, noun)
	if err != nil || len(table.Rows) == 0 {
		return err
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	return table.Render(w)
}

// domainKey reverses the labels of a hostname so that sorting groups hosts
// under their parent domain.
func domainKey(host string) string {
	labels := strings.Split(host, ".")
	slices.Reverse(labels)
	return strings.Join(labels, ".")
}

// abbreviate joins values, replacing everything past the first limit with a
// count.
func abbreviate(values []string, limit int) string {
	if len(values) <= limit {
		return strings.Join(values, ", ")
	}
	return fmt.Sprintf("%s (+%d)", strings.Join(values[:limit], ", "), len(values)-limit)
}
