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
func DefaultConfigLocations() []string {
	locations := []string{
		"grant.yaml",
		"grant.yml",
		".grant.yaml",
		".grant.yml",
	}

	// Add home directory locations
	if homeDir, err := homedir.Dir(); err == nil {
		locations = append(locations, []string{
			filepath.Join(homeDir, ".grant.yaml"),
			filepath.Join(homeDir, ".grant.yml"),
			filepath.Join(homeDir, ".config", "grant", "grant.yaml"),
			filepath.Join(homeDir, ".config", "grant", "grant.yml"),
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
	// If config file is explicitly provided, try to load it
	if configFile != "" {
		if _, err := os.Stat(configFile); err == nil {
			return grant.LoadPolicyFromFile(configFile)
		} else {
			return nil, fmt.Errorf("specified config file not found: %s", configFile)
		}
	}

	// Look for config files in default locations
	for _, location := range DefaultConfigLocations() {
		if _, err := os.Stat(location); err == nil {
			policy, err := grant.LoadPolicyFromFile(location)
			if err == nil {
				return policy, nil
			}
			// Continue looking if this file exists but is invalid
		}
	}

	// Return default policy
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
