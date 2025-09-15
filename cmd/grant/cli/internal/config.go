package internal

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"

	"github.com/anchore/grant/grant"
)

// Config represents the CLI configuration
type Config struct {
	ConfigFile   string
	OutputFormat string
	Quiet        bool
	Verbose      bool

	// Policy configuration
	Policy *grant.Policy
}

// DefaultConfigLocations returns the default locations to look for config files
// following the XDG Base Directory Specification
func DefaultConfigLocations() []string {
	locations := []string{
		"grant.yaml",
		"grant.yml",
		".grant.yaml",
		".grant.yml",
	}

	// Add XDG Base Directory specification locations
	// Reference: https://specifications.freedesktop.org/basedir-spec/latest/

	// XDG_CONFIG_HOME (defaults to $HOME/.config)
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		if homeDir, err := homedir.Dir(); err == nil {
			configHome = filepath.Join(homeDir, ".config")
		}
	}

	if configHome != "" {
		locations = append(locations, []string{
			filepath.Join(configHome, "grant", "grant.yaml"),
			filepath.Join(configHome, "grant", "grant.yml"),
		}...)
	}

	// XDG_CONFIG_DIRS (defaults to /etc/xdg)
	configDirs := os.Getenv("XDG_CONFIG_DIRS")
	if configDirs == "" {
		configDirs = "/etc/xdg"
	}

	for _, dir := range filepath.SplitList(configDirs) {
		if dir != "" {
			locations = append(locations, []string{
				filepath.Join(dir, "grant", "grant.yaml"),
				filepath.Join(dir, "grant", "grant.yml"),
			}...)
		}
	}

	// Add legacy home directory locations for backward compatibility
	if homeDir, err := homedir.Dir(); err == nil {
		locations = append(locations, []string{
			filepath.Join(homeDir, ".grant.yaml"),
			filepath.Join(homeDir, ".grant.yml"),
		}...)
	}

	return locations
}

// LoadConfig loads configuration from various sources
func LoadConfig(configFile string) (*Config, error) {
	config := &Config{
		ConfigFile:   configFile,
		OutputFormat: "table",
		Quiet:        false,
		Verbose:      false,
	}

	// Load policy
	policy, err := loadPolicyConfig(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load policy: %w", err)
	}
	config.Policy = policy

	return config, nil
}

// loadPolicyConfig loads policy from config file or defaults
func loadPolicyConfig(configFile string) (*grant.Policy, error) {
	// If config file is explicitly provided, it must exist and be valid
	if configFile != "" {
		if _, err := os.Stat(configFile); err == nil {
			return grant.LoadPolicyFromFile(configFile)
		} else {
			return nil, fmt.Errorf("specified config file not found: %s", configFile)
		}
	}

	// Look for config files in default locations (following XDG spec hierarchy)
	for _, location := range DefaultConfigLocations() {
		if _, err := os.Stat(location); err == nil {
			policy, err := grant.LoadPolicyFromFile(location)
			if err == nil {
				return policy, nil
			}
			// Continue looking if this file exists but is invalid
			// Log the error but don't fail the entire process
		}
	}

	// Return default policy if no config file found
	return grant.LoadPolicyOrDefault("")
}

// SaveDefaultConfig creates a default configuration file
func SaveDefaultConfig(path string) error {
	defaultConfig := `# Grant License Compliance Configuration
# See: https://github.com/anchore/grant

# List of allowed license patterns (supports glob matching)
allow:
  - "MIT"
  - "MIT-*" 
  - "Apache-2.0"
  - "Apache-2.0-*"
  - "BSD-2-Clause"
  - "BSD-3-Clause"
  - "BSD-3-Clause-Clear"
  - "ISC"
  - "0BSD"
  - "Unlicense"
  - "CC0-1.0"

# List of package patterns to ignore (supports glob matching)
ignore-packages:
  # Examples:
  # - "github.com/mycompany/*"
  # - "@mycompany/*"
  # - "mycompany-*"

# Policy options
require-license: true        # Deny packages with no detected licenses
require-known-license: false # Deny non-SPDX / unparsable licenses
`

	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Write config file
	if err := os.WriteFile(path, []byte(defaultConfig), 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// ValidateConfig validates the configuration
func ValidateConfig(config *Config) error {
	// Validate output format
	switch config.OutputFormat {
	case "json", "table":
		// Valid formats
	default:
		return fmt.Errorf("invalid output format: %s (must be 'json' or 'table')", config.OutputFormat)
	}

	// Validate policy
	if config.Policy == nil {
		return fmt.Errorf("policy is required")
	}

	return nil
}
