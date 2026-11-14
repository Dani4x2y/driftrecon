package cli

import (
	"cmp"
	"encoding/json"
	"errors"
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
		states []string
	)
	cmd := &cobra.Command{
		Use:   "assets <target>",
		Short: "List the hosts recorded by a scan",
		Long: `List the hosts recorded by a scan, by default the latest completed one.

States:
  live        resolves to at least one address
  wildcard    resolves only because of a wildcard record
  unresolved  does not exist or has no address records
  discovered  reported by a source, not resolved (passive scans)
  error       the lookup failed, nothing is known for this scan`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			filter, err := parseStates(states)
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

			var scan *storage.Scan
			if cmd.Flags().Changed("scan") {
				scan, err = store.GetScan(ctx, target.ID, scanID)
			} else {
				scan, err = store.LatestScan(ctx, target.ID)
				if errors.Is(err, storage.ErrNotFound) {
					return fmt.Errorf("target %q has no completed scan yet, run: driftrecon scan %s", target.Name, target.Name)
				}
			}
			if err != nil {
				return err
			}

			snaps, err := store.Snapshots(ctx, scan.ID)
			if err != nil {
				return err
			}
			return renderAssets(cmd.OutOrStdout(), target, scan, snaps, filter)
		},
	}

	flags := cmd.Flags()
	flags.Int64Var(&scanID, "scan", 0, "scan to show (default: latest completed scan)")
	flags.StringSliceVar(&states, "state", nil, "only show hosts in this state (repeatable)")
	return cmd
}

func parseStates(names []string) (map[model.State]bool, error) {
	filter := make(map[model.State]bool, len(names))
	for _, name := range names {
		state := model.State(strings.ToLower(name))
		if !slices.Contains(hostStates, state) {
			valid := make([]string, len(hostStates))
			for i, s := range hostStates {
				valid[i] = string(s)
			}
			return nil, fmt.Errorf("unknown state %q (want one of: %s)", name, strings.Join(valid, ", "))
		}
		filter[state] = true
	}
	return filter, nil
}

func renderAssets(w io.Writer, target *storage.Target, scan *storage.Scan, snaps []storage.AssetSnapshot, filter map[model.State]bool) error {
	slices.SortFunc(snaps, func(a, b storage.AssetSnapshot) int {
		return cmp.Compare(domainKey(a.Host), domainKey(b.Host))
	})

	table := report.Table{Header: []string{"HOST", "STATE", "ADDRESSES", "CNAME", "SOURCES", "FIRST SEEN"}}
	for _, snap := range snaps {
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
			strings.Join(snap.Sources, ","),
			snap.FirstSeenAt.Format(time.DateOnly),
		})
	}

	_, err := fmt.Fprintf(w, "scan #%d of %s (%s, %s): %d of %d hosts\n",
		scan.ID, target.Name, scan.Profile, scan.StartedAt.Format(timeFormat), len(table.Rows), len(snaps))
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
