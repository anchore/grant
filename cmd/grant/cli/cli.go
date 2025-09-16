package cli

import (
	"github.com/spf13/cobra"

	"github.com/anchore/grant/cmd/grant/cli/command"
	"github.com/anchore/grant/internal"
)

// Application constructs the grant CLI application
func Application() *cobra.Command {
	app := &cobra.Command{
		Use:     "grant",
		Short:   "A license compliance tool for container images, SBOMs, filesystems, and more",
		Long:    `Grant helps you view licenses for container images, SBOM documents, filesystems, and apply rules to build license compliance reports.`,
		Version: internal.ApplicationVersion,
	}

	// Add global flags
	app.PersistentFlags().StringP("config", "c", "", "path to configuration file")
	app.PersistentFlags().StringP("output", "o", "table", "output format (table, json)")
	app.PersistentFlags().StringP("output-file", "f", "", "write JSON output to file (sets output format to json)")
	app.PersistentFlags().BoolP("quiet", "q", false, "suppress all non-essential output")
	app.PersistentFlags().BoolP("verbose", "v", false, "enable verbose output")

	// Add subcommands
	app.AddCommand(
		command.Check(),
		command.List(),
		command.Config(),
	)

	return app
}
