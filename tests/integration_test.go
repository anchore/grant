package tests

import (
	"os"
	"testing"

	"github.com/anchore/grant/grant"
)

func TestIntegration_MinimalConfig(t *testing.T) {
	// Load minimal.yaml config
	minimalConfigData := `allow:
  - MIT
  - Apache-2.0
  - BSD-*`

	policy, err := grant.LoadPolicy([]byte(minimalConfigData))
	if err != nil {
		t.Fatalf("Failed to load minimal config: %v", err)
	}

	// Verify policy loaded correctly
	if len(policy.Allow) != 3 {
		t.Errorf("Expected 3 allowed licenses, got %d", len(policy.Allow))
	}

	// Test license permission checking
	testCases := []struct {
		license string
		allowed bool
	}{
		{"MIT", true},
		{"Apache-2.0", true},
		{"BSD-2-Clause", true},
		{"BSD-3-Clause", true},
		{"GPL-3.0", false},
		{"ISC", false},
	}

	for _, tc := range testCases {
		if got := policy.IsLicensePermitted(tc.license); got != tc.allowed {
			t.Errorf("License %s: expected %v, got %v", tc.license, tc.allowed, got)
		}
	}
}

func TestIntegration_SimplifiedBasicConfig(t *testing.T) {
	// Load simplified-basic.yaml config
	basicConfigData := `allow:
  - MIT
  - MIT-*
  - Apache-2.0
  - Apache-2.0-*
  - BSD-2-Clause
  - BSD-3-Clause
  - BSD-3-Clause-Clear
  - ISC
  - 0BSD
  - Unlicense
  - CC0-1.0

ignore-packages:
  - github.com/mycompany/*
  - "@mycompany/*"
  - mycompany-*`

	policy, err := grant.LoadPolicy([]byte(basicConfigData))
	if err != nil {
		t.Fatalf("Failed to load basic config: %v", err)
	}

	// Test license permissions
	licenseTests := []struct {
		license string
		allowed bool
	}{
		{"MIT", true},
		{"MIT-Modern-Variant", true},
		{"Apache-2.0", true},
		{"Apache-2.0-with-LLVM-exception", true},
		{"BSD-2-Clause", true},
		{"BSD-3-Clause", true},
		{"ISC", true},
		{"0BSD", true},
		{"Unlicense", true},
		{"CC0-1.0", true},
		{"GPL-3.0", false},
		{"AGPL-3.0", false},
		{"Proprietary", false},
	}

	for _, tc := range licenseTests {
		if got := policy.IsLicensePermitted(tc.license); got != tc.allowed {
			t.Errorf("License %s: expected %v, got %v", tc.license, tc.allowed, got)
		}
	}

	// Test package ignore patterns
	packageTests := []struct {
		packageName string
		ignored     bool
	}{
		{"github.com/mycompany/repo", true},
		{"github.com/mycompany/deep/nested/repo", true},
		{"@mycompany/utils", true},
		{"@mycompany/scoped/package", true},
		{"mycompany-tools", true},
		{"mycompany-internal-lib", true},
		{"github.com/other/repo", false},
		{"@other/utils", false},
		{"some-package", false},
		{"github.com/mycompany", false}, // Should not match without trailing slash
	}

	for _, tc := range packageTests {
		if got := policy.IsPackageIgnored(tc.packageName); got != tc.ignored {
			t.Errorf("Package %s: expected ignored=%v, got %v", tc.packageName, tc.ignored, got)
		}
	}
}

func TestIntegration_LoadPolicyFromExamples(t *testing.T) {
	// Test loading actual example files
	examples := []struct {
		name string
		path string
	}{
		{"minimal", "./examples/minimal.yaml"},
		{"simplified-basic", "./examples/simplified-basic.yaml"},
	}

	for _, example := range examples {
		t.Run(example.name, func(t *testing.T) {
			// Check if file exists
			if _, err := os.Stat(example.path); os.IsNotExist(err) {
				t.Skipf("Example file %s does not exist, skipping", example.path)
				return
			}

			policy, err := grant.LoadPolicyFromFile(example.path)
			if err != nil {
				t.Errorf("Failed to load policy from %s: %v", example.path, err)
				return
			}

			// Basic validation that policy loaded correctly
			if len(policy.Allow) == 0 {
				t.Errorf("Expected non-empty Allow list in %s", example.name)
			}

			// MIT should be allowed in both example configs
			if !policy.IsLicensePermitted("MIT") {
				t.Errorf("Expected MIT to be allowed in %s config", example.name)
			}

			// GPL should be denied in both example configs
			if policy.IsLicensePermitted("GPL-3.0") {
				t.Errorf("Expected GPL-3.0 to be denied in %s config", example.name)
			}
		})
	}
}

func TestIntegration_EmptyPolicy(t *testing.T) {
	// Test with empty policy (should deny everything)
	policy, err := grant.LoadPolicy([]byte(``))
	if err != nil {
		t.Fatalf("Failed to load empty policy: %v", err)
	}

	// Everything should be denied with empty policy
	testLicenses := []string{"MIT", "Apache-2.0", "BSD-2-Clause", "GPL-3.0", ""}
	for _, license := range testLicenses {
		if policy.IsLicensePermitted(license) {
			t.Errorf("Expected license %s to be denied with empty policy", license)
		}
	}

	// No packages should be ignored with empty policy
	testPackages := []string{"github.com/any/package", "internal", "test"}
	for _, pkg := range testPackages {
		if policy.IsPackageIgnored(pkg) {
			t.Errorf("Expected package %s to not be ignored with empty policy", pkg)
		}
	}
}

func TestIntegration_PolicyValidation(t *testing.T) {
	// Test various valid and invalid YAML configurations
	testCases := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{
			name: "valid minimal config",
			yaml: `allow:
  - MIT
  - Apache-2.0`,
			wantErr: false,
		},
		{
			name: "valid config with ignore-packages",
			yaml: `allow:
  - MIT
ignore-packages:
  - internal/*`,
			wantErr: false,
		},
		{
			name: "empty config is valid",
			yaml: ``,
			wantErr: false,
		},
		{
			name: "only allow section",
			yaml: `allow:
  - MIT`,
			wantErr: false,
		},
		{
			name: "only ignore-packages section",
			yaml: `ignore-packages:
  - internal/*`,
			wantErr: false,
		},
		{
			name: "invalid yaml syntax",
			yaml: `allow:
  - MIT
  invalid: [`,
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := grant.LoadPolicy([]byte(tc.yaml))
			if (err != nil) != tc.wantErr {
				t.Errorf("LoadPolicy() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestIntegration_GlobPatterns(t *testing.T) {
	policy := &grant.Policy{
		Allow: []string{
			"MIT",
			"Apache-*",
			"BSD-*-Clause",
			"*GPL*", // Dangerous but valid glob
		},
		IgnorePackages: []string{
			"github.com/company/*",
			"@scope/*",
			"prefix-*",
			"*-suffix",
		},
	}

	// Test license glob patterns
	licenseTests := []struct {
		license string
		allowed bool
	}{
		// Exact matches
		{"MIT", true},
		// Apache glob
		{"Apache-2.0", true},
		{"Apache-1.1", true},
		{"Apache-2.0-with-LLVM-exception", true},
		// BSD glob
		{"BSD-2-Clause", true},
		{"BSD-3-Clause", true},
		{"BSD-4-Clause", true},
		// GPL glob (matches anything with GPL)
		{"GPL-2.0", true},
		{"GPL-3.0", true},
		{"LGPL-2.1", true},
		{"AGPL-3.0", true},
		// Non-matches
		{"ISC", false},
		{"Unlicense", false},
		{"Custom", false},
	}

	for _, tc := range licenseTests {
		if got := policy.IsLicensePermitted(tc.license); got != tc.allowed {
			t.Errorf("License %s: expected %v, got %v", tc.license, tc.allowed, got)
		}
	}

	// Test package ignore glob patterns
	packageTests := []struct {
		packageName string
		ignored     bool
	}{
		// github.com/company/* pattern
		{"github.com/company/repo", true},
		{"github.com/company/nested/repo", true},
		{"github.com/other/repo", false},
		{"github.com/company", false},
		// @scope/* pattern
		{"@scope/package", true},
		{"@scope/nested/package", true},
		{"@other/package", false},
		// prefix-* pattern
		{"prefix-tool", true},
		{"prefix-anything", true},
		{"other-prefix", false},
		// *-suffix pattern
		{"tool-suffix", true},
		{"anything-suffix", true},
		{"suffix-other", false},
	}

	for _, tc := range packageTests {
		if got := policy.IsPackageIgnored(tc.packageName); got != tc.ignored {
			t.Errorf("Package %s: expected ignored=%v, got %v", tc.packageName, tc.ignored, got)
		}
	}
}