package command

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anchore/go-logger"
	"github.com/anchore/go-logger/adapter/logrus"
	"github.com/anchore/grant/cmd/grant/cli/internal"
	"github.com/anchore/grant/grant"
	"github.com/anchore/grant/internal/log"
	"github.com/anchore/grant/internal/stdinbuffer"
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
	NoOutput     bool
}

// GetGlobalConfig extracts global configuration from cobra command
func GetGlobalConfig(cmd *cobra.Command) *GlobalConfig {
	configFile, _ := cmd.Flags().GetString("config")
	outputFormat, _ := cmd.Flags().GetString("output")
	outputFile, _ := cmd.Flags().GetString("output-file")
	quiet, _ := cmd.Flags().GetBool("quiet")
	verbose, _ := cmd.Flags().GetBool("verbose")
	noOutput, _ := cmd.Flags().GetBool("no-output")

	// Note: If output-file is specified, we keep the original outputFormat for terminal
	// but will write JSON to the file separately

	return &GlobalConfig{
		ConfigFile:   configFile,
		OutputFormat: outputFormat,
		OutputFile:   outputFile,
		Quiet:        quiet,
		Verbose:      verbose,
		NoOutput:     noOutput,
	}
}

// SetupLogging configures logging based on verbose flag
func SetupLogging(verbose bool) {
	var logLevel logger.Level
	if verbose {
		logLevel = logger.DebugLevel
	} else {
		logLevel = logger.WarnLevel
	}

	cfg := logrus.Config{
		EnableConsole: true,
		Level:         logLevel,
	}

	l, _ := logrus.New(cfg)
	log.Set(l)
}

// LoadPolicyFromConfig loads policy based on global config
func LoadPolicyFromConfig(config *GlobalConfig) (*grant.Policy, error) {
	// Use the centralized config loading logic from internal package
	internalConfig, err := internal.LoadConfig(config.ConfigFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Log config path when verbose is enabled
	if config.Verbose {
		configPath := config.ConfigFile
		if configPath == "" {
			configPath = internal.GetResolvedConfigPath()
		}
		if configPath != "" {
			log.Debugf("config file: %s", configPath)
		} else {
			log.Debug("No configuration file found, using defaults")
		}
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
		// Always output to terminal (caller should check no-output flag)
		return output.OutputJSON(result, "")
	case formatTable:
		return output.OutputTable(result)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

// isGrantJSONInput checks if the target is stdin or a file and if it contains grant JSON output
func isGrantJSONInput(target string) (*grant.RunResponse, bool) {
	var data []byte
	var err error

	switch {
	case strings.EqualFold(target, "-"):
		// Handle stdin input
		// Check if stdin is available
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			// stdin is not available (terminal mode)
			return nil, false
		}

		// Read from stdin
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			return nil, false
		}
	case strings.HasSuffix(target, ".json"):
		// Handle file input - check if it's a JSON file that might be grant output
		// Check if the file exists
		if _, err := os.Stat(target); os.IsNotExist(err) {
			return nil, false
		}

		// Read from file
		data, err = readInputFile(target)
		if err != nil {
			return nil, false
		}
	default:
		// Not stdin and not a JSON file
		return nil, false
	}

	// Try to parse as grant RunResponse
	var result grant.RunResponse
	if err := json.Unmarshal(data, &result); err != nil {
		// Not grant JSON - if from stdin, save for SBOM processing
		if strings.EqualFold(target, "-") {
			stdinbuffer.Set(data)
		}
		return nil, false
	}

	// Check if it has the expected grant JSON structure
	if result.Tool == "grant" && result.Version != "" && len(result.Run.Targets) > 0 {
		return &result, true
	}

	// Not grant JSON - if from stdin, save for SBOM processing
	if strings.EqualFold(target, "-") {
		stdinbuffer.Set(data)
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

			// Special case: check if filtering for packages without licenses
			if filterMap["(no licenses found)"] && len(pkg.Licenses) == 0 {
				hasMatchingLicense = true
				matchedLicenses["(no licenses found)"] = true
			} else {
				// Check if package has any of the specified licenses
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

var maxUserFileBytes int64 = 100 << 20 // 100 MiB cap

// readInputFile reads a user-specified JSON or XML file with safety checks.
// It intentionally accepts arbitrary file paths but guards against symlinks, large files,
// and unsupported formats.
func readInputFile(target string) ([]byte, error) {
	// Support "-" as stdin (for piping JSON/XML)
	if target == "-" {
		return io.ReadAll(io.LimitReader(os.Stdin, maxUserFileBytes+1))
	}

	clean := filepath.Clean(target)

	// Check extension (case-insensitive)
	ext := strings.ToLower(filepath.Ext(clean))
	if ext != ".json" && ext != ".xml" {
		return nil, fmt.Errorf("unsupported file type %q (must be .json or .xml)", ext)
	}

	fi, err := os.Lstat(clean)
	if err != nil {
		return nil, fmt.Errorf("stat %q: %w", clean, err)
	}

	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing to read symlink: %s", clean)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing to read non-regular file: %s", clean)
	}
	if fi.Size() > maxUserFileBytes {
		return nil, fmt.Errorf("file too large (%d bytes > %d)", fi.Size(), maxUserFileBytes)
	}

	// #nosec G304 -- design: CLI intentionally accepts arbitrary JSON/XML file paths
	f, err := os.Open(clean)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", clean, err)
	}

	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	data, err := io.ReadAll(io.LimitReader(f, maxUserFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", clean, err)
	}
	if int64(len(data)) > maxUserFileBytes {
		return nil, errors.New("file exceeds maximum allowed size")
	}

	return data, err
}
