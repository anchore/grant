package command

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anchore/grant/cmd/grant/cli/internal"
	"github.com/anchore/grant/grant"
)

const (
	formatJSON     = "json"
	formatTable    = "table"
	unknownLicense = "(unknown)"
	noVersion      = "(no version)"
)

// GlobalConfig holds configuration that applies to all commands
type GlobalConfig struct {
	ConfigFile   string
	OutputFormat string
	OutputFile   string
	Quiet        bool
	Verbose      bool
}

// GetGlobalConfig extracts global configuration from cobra command
func GetGlobalConfig(cmd *cobra.Command) *GlobalConfig {
	configFile, _ := cmd.Flags().GetString("config")
	outputFormat, _ := cmd.Flags().GetString("output")
	outputFile, _ := cmd.Flags().GetString("output-file")
	quiet, _ := cmd.Flags().GetBool("quiet")
	verbose, _ := cmd.Flags().GetBool("verbose")

	// Note: If output-file is specified, we keep the original outputFormat for terminal
	// but will write JSON to the file separately

	return &GlobalConfig{
		ConfigFile:   configFile,
		OutputFormat: outputFormat,
		OutputFile:   outputFile,
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
func OutputResult(result *grant.RunResponse, format string, outputFile string) error {
	output := internal.NewOutput()

	// If output file is specified, always write JSON to file
	if outputFile != "" {
		if err := output.OutputJSON(result, outputFile); err != nil {
			return err
		}
	}

	// Handle terminal output based on format
	switch format {
	case formatJSON:
		// If no output file specified, write JSON to stdout
		if outputFile == "" {
			return output.OutputJSON(result, "")
		}
		// If output file is specified, we already wrote to file, so no stdout output
		return nil
	case formatTable:
		return output.OutputTable(result)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

// isGrantJSONInput checks if the target is "-" (stdin) and if stdin contains grant JSON output
func isGrantJSONInput(target string) (*grant.RunResponse, bool) {
	if !strings.EqualFold(target, "-") {
		return nil, false
	}

	// Read from stdin
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, false
	}

	// Try to parse as grant RunResponse
	var result grant.RunResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, false
	}

	// Check if it has the expected grant JSON structure
	if result.Tool == "grant" && result.Version != "" && len(result.Run.Targets) > 0 {
		return &result, true
	}

	return nil, false
}

// handleGrantJSONInput processes grant JSON input directly without re-analysis
func handleGrantJSONInput(result *grant.RunResponse, licenseFilters []string) *grant.RunResponse {
	// If no license filters, return as-is
	if len(licenseFilters) == 0 {
		return result
	}

	// Apply license filtering to the existing result
	return filterGrantJSONByLicenses(result, licenseFilters)
}

// filterGrantJSONByLicenses filters the result to only include packages that have licenses matching the specified filters
func filterGrantJSONByLicenses(result *grant.RunResponse, licenseFilters []string) *grant.RunResponse {
	// Create a map for faster license lookup
	filterMap := make(map[string]bool)
	for _, filter := range licenseFilters {
		filterMap[filter] = true
	}

	// Create a new result with filtered packages
	filteredResult := &grant.RunResponse{
		Tool:    result.Tool,
		Version: result.Version,
		Run: grant.RunDetails{
			Argv:    result.Run.Argv,
			Policy:  result.Run.Policy,
			Targets: []grant.TargetResult{},
		},
	}

	for _, target := range result.Run.Targets {
		filteredPackages := []grant.PackageFinding{}
		matchedLicenses := make(map[string]bool)
		packageMap := make(map[string]grant.PackageFinding) // For deduplication

		// Filter packages that have any of the specified licenses
		for _, pkg := range target.Evaluation.Findings.Packages {
			hasMatchingLicense := false
			for _, license := range pkg.Licenses {
				licenseKey := license.ID
				if licenseKey == "" {
					licenseKey = license.Name
				}
				if filterMap[licenseKey] {
					hasMatchingLicense = true
					matchedLicenses[licenseKey] = true
				}
			}
			if hasMatchingLicense {
				// Use package name + version as deduplication key
				packageKey := pkg.Name + "@" + pkg.Version
				packageMap[packageKey] = pkg
			}
		}

		// Convert map back to slice for deduplicated packages
		for _, pkg := range packageMap {
			filteredPackages = append(filteredPackages, pkg)
		}

		// Create filtered target with updated summary
		filteredTarget := grant.TargetResult{
			Source: target.Source,
			Evaluation: grant.TargetEvaluation{
				Status: target.Evaluation.Status,
				Summary: grant.EvaluationSummaryJSON{
					Packages: grant.PackageSummary{
						Total:      len(filteredPackages),
						Unlicensed: 0,                     // Will be calculated if needed
						Allowed:    len(filteredPackages), // All filtered packages are "allowed" for display
						Denied:     0,
						Ignored:    0,
					},
					Licenses: grant.LicenseSummary{
						Unique:  len(matchedLicenses),
						Allowed: len(matchedLicenses),
						Denied:  0,
						NonSPDX: 0, // Would need to calculate if needed
					},
				},
				Findings: grant.EvaluationFindings{
					Packages: filteredPackages,
				},
			},
		}

		filteredResult.Run.Targets = append(filteredResult.Run.Targets, filteredTarget)
	}

	return filteredResult
}
