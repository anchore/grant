package grant

import (
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func TestCase_Evaluate(t *testing.T) {
	tests := []struct {
		name           string
		packages       []Package
		policy         *Policy
		expectedResult EvaluationResult
		wantErr        bool
	}{
		{
			name: "all packages allowed",
			packages: []Package{
				{Name: "package1", Licenses: []License{{SPDXExpression: "MIT"}}},
				{Name: "package2", Licenses: []License{{SPDXExpression: "Apache-2.0"}}},
			},
			policy: &Policy{
				Allow: []string{"MIT", "Apache-2.0"},
			},
			expectedResult: EvaluationResult{
				AllowedPackages: []PackageResult{
					{
						Package:         Package{Name: "package1", Licenses: []License{{SPDXExpression: "MIT"}}},
						AllowedLicenses: []License{{SPDXExpression: "MIT"}},
						Reason:          "all licenses allowed",
					},
					{
						Package:         Package{Name: "package2", Licenses: []License{{SPDXExpression: "Apache-2.0"}}},
						AllowedLicenses: []License{{SPDXExpression: "Apache-2.0"}},
						Reason:          "all licenses allowed",
					},
				},
				DeniedPackages:  []PackageResult{},
				IgnoredPackages: []PackageResult{},
				Summary: EvaluationSummary{
					TotalPackages:   2,
					AllowedPackages: 2,
					DeniedPackages:  0,
					IgnoredPackages: 0,
				},
			},
		},
		{
			name: "mixed allowed and denied packages",
			packages: []Package{
				{Name: "good-package", Licenses: []License{{SPDXExpression: "MIT"}}},
				{Name: "bad-package", Licenses: []License{{SPDXExpression: "GPL-3.0"}}},
			},
			policy: &Policy{
				Allow: []string{"MIT", "Apache-2.0"},
			},
			expectedResult: EvaluationResult{
				AllowedPackages: []PackageResult{
					{
						Package:         Package{Name: "good-package", Licenses: []License{{SPDXExpression: "MIT"}}},
						AllowedLicenses: []License{{SPDXExpression: "MIT"}},
						Reason:          "all licenses allowed",
					},
				},
				DeniedPackages: []PackageResult{
					{
						Package:        Package{Name: "bad-package", Licenses: []License{{SPDXExpression: "GPL-3.0"}}},
						DeniedLicenses: []License{{SPDXExpression: "GPL-3.0"}},
						Reason:         "package denied due to 1 denied licenses",
					},
				},
				IgnoredPackages: []PackageResult{},
				Summary: EvaluationSummary{
					TotalPackages:   2,
					AllowedPackages: 1,
					DeniedPackages:  1,
					IgnoredPackages: 0,
				},
			},
		},
		{
			name: "packages with no licenses denied",
			packages: []Package{
				{Name: "no-license-package", Licenses: []License{}},
				{Name: "good-package", Licenses: []License{{SPDXExpression: "MIT"}}},
			},
			policy: &Policy{
				Allow:          []string{"MIT"},
				RequireLicense: true,
			},
			expectedResult: EvaluationResult{
				AllowedPackages: []PackageResult{
					{
						Package:         Package{Name: "good-package", Licenses: []License{{SPDXExpression: "MIT"}}},
						AllowedLicenses: []License{{SPDXExpression: "MIT"}},
						Reason:          "all licenses allowed",
					},
				},
				DeniedPackages: []PackageResult{
					{
						Package: Package{Name: "no-license-package", Licenses: []License{}},
						Reason:  "package denied - no licenses found",
					},
				},
				IgnoredPackages: []PackageResult{},
				Summary: EvaluationSummary{
					TotalPackages:   2,
					AllowedPackages: 1,
					DeniedPackages:  1,
					IgnoredPackages: 0,
				},
			},
		},
		{
			name: "ignored packages",
			packages: []Package{
				{Name: "github.com/mycompany/internal", Licenses: []License{{SPDXExpression: "GPL-3.0"}}},
				{Name: "external-package", Licenses: []License{{SPDXExpression: "MIT"}}},
			},
			policy: &Policy{
				Allow:          []string{"MIT"},
				IgnorePackages: []string{"github.com/mycompany/*"},
			},
			expectedResult: EvaluationResult{
				AllowedPackages: []PackageResult{
					{
						Package:         Package{Name: "external-package", Licenses: []License{{SPDXExpression: "MIT"}}},
						AllowedLicenses: []License{{SPDXExpression: "MIT"}},
						Reason:          "all licenses allowed",
					},
				},
				DeniedPackages: []PackageResult{},
				IgnoredPackages: []PackageResult{
					{
						Package: Package{Name: "github.com/mycompany/internal", Licenses: []License{{SPDXExpression: "GPL-3.0"}}},
						Reason:  "package ignored per policy",
					},
				},
				Summary: EvaluationSummary{
					TotalPackages:   2,
					AllowedPackages: 1,
					DeniedPackages:  0,
					IgnoredPackages: 1,
				},
			},
		},
		{
			name: "package with mixed licenses - some allowed some denied",
			packages: []Package{
				{Name: "mixed-package", Licenses: []License{
					{SPDXExpression: "MIT"},
					{SPDXExpression: "GPL-3.0"},
				}},
			},
			policy: &Policy{
				Allow: []string{"MIT"},
			},
			expectedResult: EvaluationResult{
				AllowedPackages: []PackageResult{},
				DeniedPackages: []PackageResult{
					{
						Package:         Package{Name: "mixed-package", Licenses: []License{{SPDXExpression: "MIT"}, {SPDXExpression: "GPL-3.0"}}},
						AllowedLicenses: []License{{SPDXExpression: "MIT"}},
						DeniedLicenses:  []License{{SPDXExpression: "GPL-3.0"}},
						Reason:          "package denied due to 1 denied licenses",
					},
				},
				IgnoredPackages: []PackageResult{},
				Summary: EvaluationSummary{
					TotalPackages:   1,
					AllowedPackages: 0,
					DeniedPackages:  1,
					IgnoredPackages: 0,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := createCaseFromPackages(tt.packages)

			result, err := c.Evaluate(tt.policy)
			if (err != nil) != tt.wantErr {
				t.Errorf("Case.Evaluate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !evaluationResultsEqual(*result, tt.expectedResult) {
				t.Errorf("Case.Evaluate() got = %+v, want %+v", *result, tt.expectedResult)
			}
		})
	}
}

func TestCase_Evaluate_NilPolicy(t *testing.T) {
	c := &Case{}
	result, err := c.Evaluate(nil)
	if err == nil {
		t.Error("Case.Evaluate() with nil policy should return error")
	}
	if result != nil {
		t.Error("Case.Evaluate() with nil policy should return nil result")
	}
}

func TestEvaluationResult_HasDeniedPackages(t *testing.T) {
	tests := []struct {
		name   string
		result EvaluationResult
		want   bool
	}{
		{
			name: "has denied packages",
			result: EvaluationResult{
				DeniedPackages: []PackageResult{{Package: Package{Name: "denied"}}},
			},
			want: true,
		},
		{
			name: "no denied packages",
			result: EvaluationResult{
				AllowedPackages: []PackageResult{{Package: Package{Name: "allowed"}}},
			},
			want: false,
		},
		{
			name:   "empty result",
			result: EvaluationResult{},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.HasDeniedPackages(); got != tt.want {
				t.Errorf("EvaluationResult.HasDeniedPackages() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvaluationResult_IsCompliant(t *testing.T) {
	tests := []struct {
		name   string
		result EvaluationResult
		want   bool
	}{
		{
			name: "compliant - only allowed packages",
			result: EvaluationResult{
				AllowedPackages: []PackageResult{{Package: Package{Name: "allowed"}}},
			},
			want: true,
		},
		{
			name: "compliant - only ignored packages",
			result: EvaluationResult{
				IgnoredPackages: []PackageResult{{Package: Package{Name: "ignored"}}},
			},
			want: true,
		},
		{
			name: "compliant - allowed and ignored",
			result: EvaluationResult{
				AllowedPackages: []PackageResult{{Package: Package{Name: "allowed"}}},
				IgnoredPackages: []PackageResult{{Package: Package{Name: "ignored"}}},
			},
			want: true,
		},
		{
			name: "not compliant - has denied packages",
			result: EvaluationResult{
				AllowedPackages: []PackageResult{{Package: Package{Name: "allowed"}}},
				DeniedPackages:  []PackageResult{{Package: Package{Name: "denied"}}},
			},
			want: false,
		},
		{
			name:   "compliant - empty result",
			result: EvaluationResult{},
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.IsCompliant(); got != tt.want {
				t.Errorf("EvaluationResult.IsCompliant() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Helper function to create a Case from packages for testing
func createCaseFromPackages(packages []Package) *Case {
	// Create a simple SBOM with the packages
	sb := sbom.SBOM{
		Source: source.Description{Name: "test"},
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(),
		},
	}

	// Convert grant packages back to syft packages and add to SBOM
	for _, grantPkg := range packages {
		syftPkg := pkg.Package{
			Name:     grantPkg.Name,
			Version:  grantPkg.Version,
			Type:     pkg.Type(grantPkg.Type),
			Licenses: pkg.NewLicenseSet(),
		}

		// Add licenses to syft package
		for _, license := range grantPkg.Licenses {
			var syftLicense pkg.License
			if license.SPDXExpression != "" {
				syftLicense = pkg.License{
					SPDXExpression: license.SPDXExpression,
				}
			} else {
				syftLicense = pkg.License{
					Value: license.Name,
				}
			}
			syftPkg.Licenses.Add(syftLicense)
		}

		sb.Artifacts.Packages.Add(syftPkg)
	}

	return &Case{
		SBOMS:    []sbom.SBOM{sb},
		Licenses: []License{},
	}
}

func evaluationResultsEqual(a, b EvaluationResult) bool {
	if !packageResultSlicesEqual(a.AllowedPackages, b.AllowedPackages) {
		return false
	}
	if !packageResultSlicesEqual(a.DeniedPackages, b.DeniedPackages) {
		return false
	}
	if !packageResultSlicesEqual(a.IgnoredPackages, b.IgnoredPackages) {
		return false
	}
	return a.Summary == b.Summary
}

func packageResultSlicesEqual(a, b []PackageResult) bool {
	if len(a) != len(b) {
		return false
	}

	// Create maps for order-independent comparison
	aMap := make(map[string]PackageResult)
	bMap := make(map[string]PackageResult)

	for _, pkg := range a {
		aMap[pkg.Package.Name] = pkg
	}
	for _, pkg := range b {
		bMap[pkg.Package.Name] = pkg
	}

	// Compare each package
	for name, aPkg := range aMap {
		bPkg, exists := bMap[name]
		if !exists {
			return false
		}
		if !packageResultEqual(aPkg, bPkg) {
			return false
		}
	}

	return true
}

func packageResultEqual(a, b PackageResult) bool {
	// Compare all Package fields
	if a.Package.Name != b.Package.Name {
		return false
	}
	if a.Package.Type != b.Package.Type {
		return false
	}
	if a.Package.Version != b.Package.Version {
		return false
	}
	// Compare Package licenses
	if !licenseSlicesEqual(a.Package.Licenses, b.Package.Licenses) {
		return false
	}
	// Compare reason
	if a.Reason != b.Reason {
		return false
	}
	if !licenseSlicesEqual(a.AllowedLicenses, b.AllowedLicenses) {
		return false
	}
	if !licenseSlicesEqual(a.DeniedLicenses, b.DeniedLicenses) {
		return false
	}
	return true
}

func licenseSlicesEqual(a, b []License) bool {
	if len(a) != len(b) {
		return false
	}

	// Create maps for order-independent comparison based on SPDX expression or name
	aMap := make(map[string]License)
	bMap := make(map[string]License)

	for _, lic := range a {
		key := lic.SPDXExpression
		if key == "" {
			key = lic.Name
		}
		aMap[key] = lic
	}
	for _, lic := range b {
		key := lic.SPDXExpression
		if key == "" {
			key = lic.Name
		}
		bMap[key] = lic
	}

	// Compare each license by key fields only (ignore internal fields like ID)
	for key, aLic := range aMap {
		bLic, exists := bMap[key]
		if !exists {
			return false
		}
		// Compare SPDX expressions if both have them
		if aLic.SPDXExpression != "" && bLic.SPDXExpression != "" {
			if aLic.SPDXExpression != bLic.SPDXExpression {
				return false
			}
		} else if aLic.SPDXExpression == "" && bLic.SPDXExpression == "" {
			// Both don't have SPDX, compare names
			if aLic.Name != bLic.Name {
				return false
			}
		} else {
			// One has SPDX, one doesn't - they're different
			return false
		}
	}

	return true
}
