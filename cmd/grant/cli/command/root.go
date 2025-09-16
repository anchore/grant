package command

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/anchore/grant/cmd/grant/cli/internal"
	"github.com/anchore/grant/grant"
)

const (
	formatJSON = "json"
)

// GlobalConfig holds configuration that applies to all commands
type GlobalConfig struct {
	ConfigFile   string
	OutputFormat string
	Quiet        bool
	Verbose      bool
}

// GetGlobalConfig extracts global configuration from cobra command
func GetGlobalConfig(cmd *cobra.Command) *GlobalConfig {
	configFile, _ := cmd.Flags().GetString("config")
	outputFormat, _ := cmd.Flags().GetString("output")
	quiet, _ := cmd.Flags().GetBool("quiet")
	verbose, _ := cmd.Flags().GetBool("verbose")

	return &GlobalConfig{
		ConfigFile:   configFile,
		OutputFormat: outputFormat,
		Quiet:        quiet,
		Verbose:      verbose,
	}
}

// LoadPolicyFromConfig loads policy based on global config
func LoadPolicyFromConfig(config *GlobalConfig) (*grant.Policy, error) {
	// Use the centralized config loading logic from internal package
	internalConfig, err := internal.LoadConfig(config.ConfigFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	return internalConfig.Policy, nil
}

// HandleError handles command errors consistently
func HandleError(err error, quiet bool) {
	if err != nil && !quiet {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}
}

// OutputResult outputs the result in the specified format
func OutputResult(result *grant.RunResponse, format string) error {
	output := internal.NewOutput()

	switch format {
	case formatJSON:
		return output.OutputJSON(result)
	case "table":
		return output.OutputTable(result)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}
