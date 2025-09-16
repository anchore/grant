package command

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/anchore/grant/internal"
)

// Version creates the version command
func Version() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show the version information for grant",
		Run: func(cmd *cobra.Command, args []string) {
			info := internal.GetBuildInfo()

			fmt.Printf("Application:    %s\n", info.Application)
			fmt.Printf("Version:        %s\n", info.Version)
			fmt.Printf("BuildDate:      %s\n", info.BuildDate)
			fmt.Printf("GitCommit:      %s\n", info.GitCommit)
			fmt.Printf("GitDescription: %s\n", info.GitDescription)
			fmt.Printf("Platform:       %s\n", info.Platform)
			fmt.Printf("GoVersion:      %s\n", info.GoVersion)
			fmt.Printf("Compiler:       %s\n", info.Compiler)
		},
	}
}