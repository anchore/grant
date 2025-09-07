package grant

import (
	"testing"
)

func TestLoadPolicy(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		expected Policy
		wantErr  bool
	}{
		{
			name: "minimal config",
			yaml: `allow:
  - MIT
  - Apache-2.0
  - BSD-*`,
			expected: Policy{
				Allow: []string{"MIT", "Apache-2.0", "BSD-*"},
			},
		},
		{
			name: "config with ignore-packages",
			yaml: `allow:
  - MIT
  - Apache-2.0
ignore-packages:
  - github.com/mycompany/*
  - @mycompany/*
  - internal-*`,
			expected: Policy{
				Allow:          []string{"MIT", "Apache-2.0"},
				IgnorePackages: []string{"github.com/mycompany/*", "@mycompany/*", "internal-*"},
			},
		},
		{
			name:     "empty config",
			yaml:     ``,
			expected: Policy{},
		},
		{
			name: "only ignore-packages",
			yaml: `ignore-packages:
  - github.com/anchore/*`,
			expected: Policy{
				IgnorePackages: []string{"github.com/anchore/*"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy, err := LoadPolicy([]byte(tt.yaml))
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadPolicy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !policiesEqual(*policy, tt.expected) {
				t.Errorf("LoadPolicy() = %v, want %v", *policy, tt.expected)
			}
		})
	}
}

func TestPolicy_IsLicensePermitted(t *testing.T) {
	policy := &Policy{
		Allow: []string{"MIT", "Apache-2.0", "BSD-*", "GPL-3.0+"},
	}

	tests := []struct {
		name    string
		license string
		want    bool
	}{
		{"exact match MIT", "MIT", true},
		{"exact match Apache", "Apache-2.0", true},
		{"glob match BSD-2", "BSD-2-Clause", true},
		{"glob match BSD-3", "BSD-3-Clause", true},
		{"exact match GPL with plus", "GPL-3.0+", true},
		{"denied license GPL-2.0", "GPL-2.0", false},
		{"denied license ISC", "ISC", false},
		{"empty license", "", false},
		{"case sensitive", "mit", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := policy.IsLicensePermitted(tt.license); got != tt.want {
				t.Errorf("Policy.IsLicensePermitted(%q) = %v, want %v", tt.license, got, tt.want)
			}
		})
	}
}

func TestPolicy_IsLicensePermitted_EmptyAllow(t *testing.T) {
	policy := &Policy{
		Allow: []string{},
	}

	tests := []struct {
		license string
		want    bool
	}{
		{"MIT", false},
		{"Apache-2.0", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.license, func(t *testing.T) {
			if got := policy.IsLicensePermitted(tt.license); got != tt.want {
				t.Errorf("Policy.IsLicensePermitted(%q) with empty allow = %v, want %v", tt.license, got, tt.want)
			}
		})
	}
}

func TestPolicy_IsPackageIgnored(t *testing.T) {
	policy := &Policy{
		IgnorePackages: []string{
			"github.com/mycompany/*",
			"@mycompany/*",
			"internal",
			"test-*",
			"crew",
		},
	}

	tests := []struct {
		name        string
		packageName string
		want        bool
	}{
		// Exact matches
		{"exact match internal", "internal", true},
		{"exact match crew", "crew", true},

		// Glob patterns with /*
		{"github glob match", "github.com/mycompany/repo", true},
		{"github glob match nested", "github.com/mycompany/deep/repo", true},
		{"npm scoped package match", "@mycompany/utils", true},
		{"npm scoped package nested", "@mycompany/deep/utils", true},

		// Glob patterns with *
		{"prefix match test", "test-utils", true},
		{"prefix match test-package", "test-package-name", true},

		// Non-matches
		{"similar but not matching github", "github.com/mycompany", false},
		{"different org", "github.com/other/repo", false},
		{"different npm scope", "@other/utils", false},
		{"partial prefix", "tes", false},
		{"empty package", "", false},
		{"case sensitive", "Internal", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := policy.IsPackageIgnored(tt.packageName); got != tt.want {
				t.Errorf("Policy.IsPackageIgnored(%q) = %v, want %v", tt.packageName, got, tt.want)
			}
		})
	}
}

func TestPolicy_IsPackageIgnored_EmptyIgnorePackages(t *testing.T) {
	policy := &Policy{
		IgnorePackages: []string{},
	}

	tests := []string{"github.com/mycompany/repo", "internal", "test", ""}
	for _, packageName := range tests {
		t.Run(packageName, func(t *testing.T) {
			if got := policy.IsPackageIgnored(packageName); got != false {
				t.Errorf("Policy.IsPackageIgnored(%q) with empty ignore = %v, want false", packageName, got)
			}
		})
	}
}

func policiesEqual(a, b Policy) bool {
	if !stringSlicesEqual(a.Allow, b.Allow) {
		return false
	}
	if !stringSlicesEqual(a.IgnorePackages, b.IgnorePackages) {
		return false
	}
	return true
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}