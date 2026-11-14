package cli

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Dani4x2y/driftrecon/internal/report"
	"github.com/Dani4x2y/driftrecon/internal/scope"
)

var targetName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

func newTargetCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "target",
		Short: "Manage scan targets",
	}
	cmd.AddCommand(newTargetAddCmd(a), newTargetListCmd(a))
	return cmd
}

func newTargetAddCmd(a *app) *cobra.Command {
	var (
		rules      scope.Rules
		authorized bool
	)
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Register a target and its scope",
		Long: `Register a target: a name for a set of root domains.

Everything under the roots is in scope unless an --exclude pattern matches.
With --include, only matching hosts are covered. Patterns are globs in which
"*" also spans dots, so "*.corp.example.com" covers every depth below
corp.example.com.`,
		Example: `  driftrecon target add acme --root example.com --root example.org --authorized
  driftrecon target add acme --root example.com --exclude '*.corp.example.com' --authorized`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if !targetName.MatchString(name) {
				return fmt.Errorf("invalid target name %q: use lower-case letters, digits, '-' and '_'", name)
			}
			if !authorized {
				return errors.New("refusing to add a target without --authorized: " +
					"pass it to confirm that you own these domains or have permission to assess them")
			}
			sc, err := scope.New(rules)
			if err != nil {
				return err
			}

			_, store, err := a.open(cmd.Context())
			if err != nil {
				return err
			}
			defer store.Close()

			target, err := store.CreateTarget(cmd.Context(), name, sc.Rules(), time.Now())
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "target %q added: %s\n",
				target.Name, strings.Join(target.Rules.Roots, ", "))
			return err
		},
	}

	flags := cmd.Flags()
	flags.StringSliceVar(&rules.Roots, "root", nil, "root domain in scope (repeatable)")
	flags.StringSliceVar(&rules.Include, "include", nil, "only cover hosts matching this glob (repeatable)")
	flags.StringSliceVar(&rules.Exclude, "exclude", nil, "never touch hosts matching this glob (repeatable)")
	flags.BoolVar(&authorized, "authorized", false, "confirm you are authorised to assess the root domains")
	return cmd
}

func newTargetListCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List targets",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, store, err := a.open(cmd.Context())
			if err != nil {
				return err
			}
			defer store.Close()

			targets, err := store.ListTargets(cmd.Context())
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if len(targets) == 0 {
				_, err := fmt.Fprintln(out, "no targets yet, add one with: driftrecon target add <name> --root <domain> --authorized")
				return err
			}

			table := report.Table{Header: []string{"NAME", "ROOTS", "HOSTS", "SCANS", "LAST SCAN"}}
			for _, t := range targets {
				last := "never"
				if !t.LastScanAt.IsZero() {
					last = t.LastScanAt.Format(timeFormat)
				}
				table.Rows = append(table.Rows, []string{
					t.Name,
					strings.Join(t.Rules.Roots, ", "),
					strconv.Itoa(t.Hosts),
					strconv.Itoa(t.Scans),
					last,
				})
			}
			return table.Render(out)
		},
	}
}
