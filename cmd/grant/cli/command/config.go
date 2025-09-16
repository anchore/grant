package command

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// FullConfig represents all possible configuration options for Grant
// This struct combines policy options with CLI options that can be set in config
type FullConfig struct {
	// Global CLI options
	Config  string `yaml:"config,omitempty"`
	Format  string `yaml:"format"`
	Quiet   bool   `yaml:"quiet"`
	Verbose bool   `yaml:"verbose"`

	// Core policy configuration (fields from grant.Policy but without omitempty for booleans)
	Allow               []string `yaml:"allow,omitempty"`
	IgnorePackages      []string `yaml:"ignore-packages"`
	RequireLicense      bool     `yaml:"require-license"`
	RequireKnownLicense bool     `yaml:"require-known-license"`

	// Command-specific options
	DisableFileSearch bool `yaml:"disable-file-search"`
	Summary           bool `yaml:"summary"`
	OnlyUnlicensed    bool `yaml:"only-unlicensed"`
}

// Config creates the config command
func Config() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Generate a comprehensive configuration file",
		Long: `Generate a complete YAML configuration file with all available Grant options.

This command outputs a comprehensive configuration file that includes:
- License policy options (allow lists, ignore patterns)
- Command-line options with defaults
- Detailed comments explaining each option

The generated configuration can be saved to a file and customized as needed.`,
		RunE: runConfig,
	}

	// Add command-specific flags
	cmd.Flags().StringP("output", "o", "", "output file path (default: stdout)")

	return cmd
}

// runConfig executes the config command
func runConfig(cmd *cobra.Command, args []string) error {
	outputFile, _ := cmd.Flags().GetString("output")

	config, err := generateConfig()
	if err != nil {
		return fmt.Errorf("failed to generate config: %w", err)
	}

	// Output to file or stdout
	if outputFile != "" {
		// Create directory if it doesn't exist
		dir := filepath.Dir(outputFile)
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}

		// Write config file
		if err := os.WriteFile(outputFile, []byte(config), 0600); err != nil {
			return fmt.Errorf("failed to write config file: %w", err)
		}

		fmt.Printf("Configuration written to: %s\n", outputFile)
	} else {
		fmt.Print(config)
	}

	return nil
}

// generateConfig generates a comprehensive configuration file
func generateConfig() (string, error) {
	// Create a default configuration with common examples
	config := FullConfig{
		Format: "table",
		Allow: []string{
			"MIT",
			"Apache-2.0",
			"BSD-3-Clause",
		},
		IgnorePackages:      []string{},
		RequireLicense:      true,
		RequireKnownLicense: false,
		DisableFileSearch:   false,
		Summary:             false,
		OnlyUnlicensed:      false,
	}

	// Generate YAML with comments
	result, err := generateConfigWithComments(&config)
	if err != nil {
		return "", fmt.Errorf("failed to generate config with comments: %w", err)
	}

	return result, nil
}

// generateConfigWithComments creates a comprehensive YAML config with detailed comments
func generateConfigWithComments(fullConfig *FullConfig) (string, error) {
	yamlData, err := yaml.Marshal(fullConfig)
	if err != nil {
		return "", fmt.Errorf("failed to marshal config: %w", err)
	}

	yamlLines := strings.Split(string(yamlData), "\n")
	var result strings.Builder

	addConfigHeader(&result)
	processYAMLLines(&result, yamlLines, fullConfig)

	return result.String(), nil
}

// addConfigHeader adds the standard header to the configuration file
func addConfigHeader(result *strings.Builder) {
	result.WriteString(`# Grant License Compliance Configuration
# Complete configuration file with all available options
# See: https://github.com/anchore/grant

`)
}

// processYAMLLines processes each YAML line and adds appropriate comments
func processYAMLLines(result *strings.Builder, yamlLines []string, fullConfig *FullConfig) {
	for _, line := range yamlLines {
		if strings.TrimSpace(line) == "" {
			result.WriteString("\n")
			continue
		}

		processConfigLine(result, line, fullConfig)
	}
}

// processConfigLine processes a single configuration line and adds comments
func processConfigLine(result *strings.Builder, line string, fullConfig *FullConfig) {
	fieldName := getFieldName(line)

	switch fieldName {
	case "config:":
		result.WriteString(line + " # Configuration file path (can be overridden with --config flag)\n")
	case "format:":
		result.WriteString(line + ` # Output format: "table" or "json" (default: "table")` + "\n")
	case "quiet:":
		result.WriteString(line + " # Suppress all non-essential output (default: false)\n")
	case "verbose:":
		result.WriteString(line + " # Enable verbose output (default: false)\n")
	case "allow:":
		result.WriteString(`# List of allowed license patterns (supports glob matching)
# Default behavior: DENY all licenses except those explicitly permitted
` + line + "\n")
	case "ignore-packages:":
		result.WriteString(`# List of package patterns to ignore from license checking
# Supports glob patterns for flexible matching
` + line + "\n")
		if len(fullConfig.IgnorePackages) == 0 {
			addIgnorePackageExamples(result)
		}
	case "require-license:":
		result.WriteString(`# Policy enforcement options
` + line + " # When true, deny packages with no detected licenses\n")
	case "require-known-license:":
		result.WriteString(line + " # When true, deny non-SPDX / unparsable licenses\n")
	case "disable-file-search:":
		result.WriteString(`
# ============================================================================
# COMMAND-SPECIFIC OPTIONS
# ============================================================================
` + line + " # Disable filesystem license file search\n")
	case "summary:":
		result.WriteString(line + " # Show only summary information for check command\n")
	case "only-unlicensed:":
		result.WriteString("# Show only packages without licenses (default: false)\n")
		result.WriteString(line + " # maps to grant check --unlicensed || grant list --unlicensed\n")
	default:
		result.WriteString(line + "\n")
	}
}

// getFieldName extracts the field name from a YAML line
func getFieldName(line string) string {
	for _, prefix := range []string{
		"config:", "format:", "quiet:", "verbose:", "allow:", "ignore-packages:",
		"require-license:", "require-known-license:", "disable-file-search:",
		"summary:", "only-unlicensed:",
	} {
		if strings.HasPrefix(line, prefix) {
			return prefix
		}
	}
	return ""
}

// addIgnorePackageExamples adds example comments for empty ignore-packages field
func addIgnorePackageExamples(result *strings.Builder) {
	result.WriteString("  # Add package patterns to ignore here\n")
	result.WriteString("  # Examples:\n")
	result.WriteString("  # - \"github.com/mycompany/*\"\n")
	result.WriteString("  # - \"internal/*\"\n")
}
