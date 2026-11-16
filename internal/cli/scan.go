package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/spf13/cobra"
	"golang.org/x/time/rate"

	"github.com/Dani4x2y/driftrecon/internal/collector"
	"github.com/Dani4x2y/driftrecon/internal/collector/ctlog"
	"github.com/Dani4x2y/driftrecon/internal/collector/resolve"
	"github.com/Dani4x2y/driftrecon/internal/config"
	"github.com/Dani4x2y/driftrecon/internal/engine"
	"github.com/Dani4x2y/driftrecon/internal/model"
	"github.com/Dani4x2y/driftrecon/internal/storage"
)

// timeFormat is used wherever a timestamp is shown to a person.
const timeFormat = "2006-01-02 15:04 MST"

// hostStates lists the states in the order they are reported.
var hostStates = []model.State{
	model.StateLive,
	model.StateWildcard,
	model.StateUnresolved,
	model.StateDiscovered,
	model.StateError,
}

func newScanCmd(a *app) *cobra.Command {
	var (
		profile     string
		concurrency int
		qps         float64
		maxHosts    int
	)
	cmd := &cobra.Command{
		Use:   "scan <target>",
		Short: "Scan a target and store a snapshot",
		Long: `Scan a target and store what was found as a new snapshot.

Profiles:
  passive   query Certificate Transparency only; nothing is sent to the target
  standard  additionally resolve every discovered name`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			prof, err := model.ParseProfile(profile)
			if err != nil {
				return err
			}

			cfg, store, err := a.open(cmd.Context())
			if err != nil {
				return err
			}
			defer store.Close()

			flags := cmd.Flags()
			if flags.Changed("concurrency") {
				cfg.Concurrency = concurrency
			}
			if flags.Changed("rate") {
				cfg.Rate = qps
			}
			if flags.Changed("max-hosts") {
				cfg.MaxHosts = maxHosts
			}
			if err := cfg.Validate(); err != nil {
				return err
			}

			target, err := store.GetTarget(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			eng, err := newEngine(cfg, store, prof, a.logger(cmd.ErrOrStderr()))
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), cfg.ScanTimeout)
			defer cancel()

			scan, scanErr := eng.Scan(ctx, target)
			if scan != nil {
				if err := printScanSummary(cmd.OutOrStdout(), target, scan); err != nil {
					return err
				}
			}
			switch {
			case errors.Is(scanErr, context.Canceled):
				return errors.New("scan interrupted")
			case errors.Is(scanErr, context.DeadlineExceeded):
				return fmt.Errorf("scan exceeded the time limit of %s", cfg.ScanTimeout)
			}
			return scanErr
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&profile, "profile", string(model.ProfileStandard), "scan profile: passive or standard")
	flags.IntVar(&concurrency, "concurrency", 0, "parallel workers (overrides the config file)")
	flags.Float64Var(&qps, "rate", 0, "DNS queries per second (overrides the config file)")
	flags.IntVar(&maxHosts, "max-hosts", 0, "refuse to scan more hosts than this (overrides the config file)")
	return cmd
}

func newEngine(cfg config.Config, store *storage.Store, profile model.Profile, log *slog.Logger) (*engine.Engine, error) {
	var sources []collector.Source
	if src := cfg.Sources.CrtSh; src.Enabled {
		sources = append(sources, ctlog.NewCrtSh(ctlog.Options{
			UserAgent: cfg.UserAgent,
			BaseURL:   src.URL,
		}))
	}
	if src := cfg.Sources.CertSpotter; src.Enabled {
		sources = append(sources, ctlog.NewCertSpotter(ctlog.Options{
			UserAgent: cfg.UserAgent,
			BaseURL:   src.URL,
			Token:     cfg.CertSpotterToken,
		}))
	}

	var resolver *resolve.Resolver
	if profile != model.ProfilePassive {
		// A burst of a tenth of a second keeps workers from queueing behind
		// timer granularity without letting the rate overshoot noticeably.
		limiter := rate.NewLimiter(rate.Limit(cfg.Rate), max(1, int(cfg.Rate/10)))

		var err error
		resolver, err = resolve.New(resolve.Options{
			Servers: cfg.Resolvers,
			Timeout: cfg.Timeout,
			Limiter: limiter,
		})
		if err != nil {
			return nil, err
		}
	}

	return engine.New(store, sources, resolver, nil, engine.Options{
		Profile:     profile,
		Concurrency: cfg.Concurrency,
		MaxHosts:    cfg.MaxHosts,
		Logger:      log,
	})
}

func printScanSummary(w io.Writer, target *storage.Target, scan *storage.Scan) error {
	var b []byte
	b = fmt.Appendf(b, "scan #%d of %s %s in %s (profile: %s)\n",
		scan.ID, target.Name, scan.Status, scan.FinishedAt.Sub(scan.StartedAt), scan.Profile)
	if scan.Stats.Reason != "" {
		b = fmt.Appendf(b, "  reason: %s\n", scan.Stats.Reason)
	}

	b = fmt.Appendf(b, "  hosts: %d in scope, %d new\n", scan.Stats.Hosts, scan.Stats.NewHosts)
	for _, state := range hostStates {
		if n := scan.Stats.States[state]; n > 0 {
			b = fmt.Appendf(b, "    %-11s %d\n", state, n)
		}
	}
	for _, src := range scan.Stats.Sources {
		b = fmt.Appendf(b, "  source %s (%s): %d names", src.Source, src.Domain, src.Names)
		if src.Error != "" {
			b = fmt.Appendf(b, ", failed: %s", src.Error)
		}
		b = append(b, '\n')
	}
	_, err := w.Write(b)
	return err
}
