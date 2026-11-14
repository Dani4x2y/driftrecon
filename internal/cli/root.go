// Package cli wires the command line interface.
package cli

import (
	"context"
	"io"
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/Dani4x2y/driftrecon/internal/config"
	"github.com/Dani4x2y/driftrecon/internal/storage"
)

// app carries the global flags shared by all commands.
type app struct {
	configPath string
	dbPath     string
	verbosity  int
}

// New builds the root command.
func New() *cobra.Command {
	a := &app{}
	root := &cobra.Command{
		Use:   "driftrecon",
		Short: "Differential attack surface monitoring",
		Long: `DriftRecon keeps a local history of an organisation's external attack
surface and reports what changed between scans.

Use it only against assets you own or are explicitly authorised to assess.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	flags := root.PersistentFlags()
	flags.StringVar(&a.configPath, "config", "", "config file (default: config.yaml in the user config directory)")
	flags.StringVar(&a.dbPath, "db", "", "database file (default: driftrecon.db in the user config directory)")
	flags.CountVarP(&a.verbosity, "verbose", "v", "log progress to stderr, repeat for debug output")

	root.AddCommand(
		newTargetCmd(a),
		newScanCmd(a),
		newAssetsCmd(a),
		newVersionCmd(),
	)
	return root
}

func (a *app) config() (config.Config, error) {
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return config.Config{}, err
	}
	if a.dbPath != "" {
		cfg.Database = a.dbPath
	}
	return cfg, nil
}

// open loads the configuration and opens the database it points to. The
// caller closes the store.
func (a *app) open(ctx context.Context) (config.Config, *storage.Store, error) {
	cfg, err := a.config()
	if err != nil {
		return config.Config{}, nil, err
	}
	store, err := storage.Open(ctx, cfg.Database)
	if err != nil {
		return config.Config{}, nil, err
	}
	return cfg, store, nil
}

func (a *app) logger(w io.Writer) *slog.Logger {
	level := slog.LevelWarn
	switch {
	case a.verbosity >= 2:
		level = slog.LevelDebug
	case a.verbosity == 1:
		level = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
}
