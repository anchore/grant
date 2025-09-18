package grant

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Policy represents a simplified grant policy that can be decoded from YAML
type Policy struct {
	// Allow is a list of permitted licenses (supports glob patterns)
	Allow []string `yaml:"allow,omitempty"`

	// IgnorePackages is a list of software package name patterns to skip license checking entirely
	// These are package manager package names (npm, Go modules, Debian packages, etc.)
	// Examples: "github.com/anchore/syft", "github.com/anchore/*", "crew", "lite"
	IgnorePackages []string `yaml:"ignore-packages,omitempty"`

	// RequireLicense when true, denies packages with no detected licenses
	RequireLicense bool `yaml:"require-license,omitempty"`

	// RequireKnownLicense when true, denies non-SPDX / unparsable licenses
	RequireKnownLicense bool `yaml:"require-known-license,omitempty"`
}

// IsLicensePermitted checks if a license is permitted by the policy
func (p *Policy) IsLicensePermitted(license string) bool {
	for _, permitted := range p.Allow {
		// Direct match
		if license == permitted {
			return true
		}

		// Convert common regex-style patterns to glob patterns
		pattern := convertRegexToGlob(permitted)

		// Glob pattern match
		if matched, err := filepath.Match(pattern, license); err == nil && matched {
			return true
		}
	}

	return false
}

// convertRegexToGlob converts common regex patterns to shell glob patterns
// This allows users to use either regex-style (BSD.*) or glob-style (BSD-*) patterns
func convertRegexToGlob(pattern string) string {
	// Replace .* (regex any) with * (glob any)
	if strings.Contains(pattern, ".*") {
		return strings.ReplaceAll(pattern, ".*", "*")
	}
	// Replace .+ (regex one or more) with * (glob any)
	if strings.Contains(pattern, ".+") {
		return strings.ReplaceAll(pattern, ".+", "*")
	}
	return pattern
}

// IsPackageIgnored checks if a software package should be ignored based on ignore-packages patterns
func (p *Policy) IsPackageIgnored(packageName string) bool {
	for _, pattern := range p.IgnorePackages {
		// Direct match
		if packageName == pattern {
			return true
		}

		// Glob pattern match - handle path-like patterns
		if matched, err := filepath.Match(pattern, packageName); err == nil && matched {
			return true
		}

		// Handle patterns like "github.com/mycompany/*"
		if strings.HasSuffix(pattern, "/*") {
			prefix := strings.TrimSuffix(pattern, "/*")
			if strings.HasPrefix(packageName, prefix+"/") {
				return true
			}
		}
	}

	return false
}

// LoadPolicy loads a policy from YAML bytes
func LoadPolicy(data []byte) (*Policy, error) {
	var policy Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy: %w", err)
	}
	return &policy, nil
}

// LoadPolicyFromFile loads a policy from a YAML file
func LoadPolicyFromFile(filename string) (*Policy, error) {
	data, err := os.ReadFile(filepath.Clean(filename))
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}
	return LoadPolicy(data)
}
