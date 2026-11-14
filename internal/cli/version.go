package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/Dani4x2y/driftrecon/internal/version"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "driftrecon %s (%s, %s/%s)\n",
				version.String(), runtime.Version(), runtime.GOOS, runtime.GOARCH)
			return err
		},
	}
}
