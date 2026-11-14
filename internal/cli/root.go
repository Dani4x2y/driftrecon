// Package cli wires the command line interface.
package cli

import "github.com/spf13/cobra"

// New builds the root command.
func New() *cobra.Command {
	root := &cobra.Command{
		Use:   "driftrecon",
		Short: "Differential attack surface monitoring",
		Long: `DriftRecon keeps a local history of an organisation's external attack
surface and reports what changed between scans.

Use it only against assets you own or are explicitly authorised to assess.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newVersionCmd())
	return root
}
