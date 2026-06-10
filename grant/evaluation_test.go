package grant

import (
	"testing"

	"github.com/anchore/syft/syft/file"
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

func TestCase_Evaluate_DuplicateCatalogedPackage(t *testing.T) {
	tests := []struct {
		name           string
		packages       []Package
		policy         *Policy
		expectedResult EvaluationResult
	}{
		{
			// The shape from issue #454: a denied license alongside a license-less
			// duplicate. The denial must win and the duplicate must not be counted
			// as a separate allowed (or unlicensed) package.
			name: "denied license plus license-less duplicate counts once",
			packages: []Package{
				{Name: "dup-pkg", Version: "1.0.0", Licenses: []License{{SPDXExpression: "BSD-3-Clause"}}},
				{Name: "dup-pkg", Version: "1.0.0", Licenses: []License{}},
			},
			policy: &Policy{Allow: []string{"MIT"}, RequireLicense: false},
			expectedResult: EvaluationResult{
				AllowedPackages: []PackageResult{},
				DeniedPackages: []PackageResult{
					{
						Package:        Package{Name: "dup-pkg", Version: "1.0.0", Licenses: []License{{SPDXExpression: "BSD-3-Clause"}}},
						DeniedLicenses: []License{{SPDXExpression: "BSD-3-Clause"}},
						Reason:         "package denied due to 1 denied licenses",
					},
				},
				IgnoredPackages: []PackageResult{},
				Summary:         EvaluationSummary{TotalPackages: 1, AllowedPackages: 0, DeniedPackages: 1, IgnoredPackages: 0},
			},
		},
		{
			// Two distinct versions of the same package must both be evaluated.
			// (Deduplicating on name alone silently dropped the second version.)
			name: "distinct versions both evaluated",
			packages: []Package{
				{Name: "multi-ver", Version: "1.0.0", Licenses: []License{{SPDXExpression: "MIT"}}},
				{Name: "multi-ver", Version: "2.0.0", Licenses: []License{{SPDXExpression: "GPL-3.0"}}},
			},
			policy: &Policy{Allow: []string{"MIT"}},
			expectedResult: EvaluationResult{
				AllowedPackages: []PackageResult{
					{
						Package:         Package{Name: "multi-ver", Version: "1.0.0", Licenses: []License{{SPDXExpression: "MIT"}}},
						AllowedLicenses: []License{{SPDXExpression: "MIT"}},
						Reason:          "all licenses allowed",
					},
				},
				DeniedPackages: []PackageResult{
					{
						Package:        Package{Name: "multi-ver", Version: "2.0.0", Licenses: []License{{SPDXExpression: "GPL-3.0"}}},
						DeniedLicenses: []License{{SPDXExpression: "GPL-3.0"}},
						Reason:         "package denied due to 1 denied licenses",
					},
				},
				IgnoredPackages: []PackageResult{},
				Summary:         EvaluationSummary{TotalPackages: 2, AllowedPackages: 1, DeniedPackages: 1, IgnoredPackages: 0},
			},
		},
		{
			// The same name@version cataloged with different licenses has its
			// licenses unioned, so a denied license is never masked by an allowed
			// one carried on a separate entry.
			name: "split licenses are unioned",
			packages: []Package{
				{Name: "split-pkg", Version: "1.0.0", Licenses: []License{{SPDXExpression: "MIT"}}},
				{Name: "split-pkg", Version: "1.0.0", Licenses: []License{{SPDXExpression: "GPL-3.0"}}},
			},
			policy: &Policy{Allow: []string{"MIT"}},
			expectedResult: EvaluationResult{
				AllowedPackages: []PackageResult{},
				DeniedPackages: []PackageResult{
					{
						Package:         Package{Name: "split-pkg", Version: "1.0.0", Licenses: []License{{SPDXExpression: "MIT"}, {SPDXExpression: "GPL-3.0"}}},
						AllowedLicenses: []License{{SPDXExpression: "MIT"}},
						DeniedLicenses:  []License{{SPDXExpression: "GPL-3.0"}},
						Reason:          "package denied due to 1 denied licenses",
					},
				},
				IgnoredPackages: []PackageResult{},
				Summary:         EvaluationSummary{TotalPackages: 1, AllowedPackages: 0, DeniedPackages: 1, IgnoredPackages: 0},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := createCaseFromPackages(tt.packages)

			result, err := c.Evaluate(tt.policy)
			if err != nil {
				t.Fatalf("Case.Evaluate() unexpected error: %v", err)
			}

			if !evaluationResultsEqual(*result, tt.expectedResult) {
				t.Errorf("Case.Evaluate() got = %+v, want %+v", *result, tt.expectedResult)
			}
		})
	}
}

func TestCase_Evaluate_MergesDuplicateLocations(t *testing.T) {
	const distInfoPath = "/.venv/lib/python3.14/site-packages/distlib-0.4.0.dist-info/METADATA"
	const lockPath = "/poetry.lock"

	packages := []Package{
		{
			Name: "distlib", Version: "0.4.0", Type: "python",
			Licenses:  []License{{SPDXExpression: "PSF-2.0"}},
			Locations: []string{distInfoPath},
		},
		{
			Name: "distlib", Version: "0.4.0", Type: "python",
			Locations: []string{lockPath},
		},
	}

	c := createCaseFromPackages(packages)
	result, err := c.Evaluate(&Policy{Allow: []string{"MIT"}, RequireLicense: false})
	if err != nil {
		t.Fatalf("Evaluate() unexpected error: %v", err)
	}

	if len(result.DeniedPackages) != 1 {
		t.Fatalf("expected the duplicate to collapse to one denied package, got %d: %+v", len(result.DeniedPackages), result.DeniedPackages)
	}

	got := result.DeniedPackages[0].Package.Locations
	if !sameStringSet(got, []string{distInfoPath, lockPath}) {
		t.Errorf("merged package must retain locations from every source, got %+v", got)
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

func TestMergeDuplicatePackages(t *testing.T) {
	// dup-pkg@1.0.0 (python) is cataloged three ways: the installed package (MIT,
	// found at its dist-info), the same install seen again with a BSD license, and
	// the lock-file entry (no license, found at the lock file). They must collapse
	// into one package that unions every license and every location.
	installed := &Package{
		Name: "dup-pkg", Version: "1.0.0", Type: "python",
		Licenses:  []License{{SPDXExpression: "MIT"}},
		Locations: []string{"/site-packages/dup-pkg-1.0.0.dist-info/METADATA"},
	}
	bsd := &Package{
		Name: "dup-pkg", Version: "1.0.0", Type: "python",
		Licenses:  []License{{SPDXExpression: "BSD-3-Clause"}},
		Locations: []string{"/site-packages/dup-pkg-1.0.0.dist-info/METADATA"}, // same path, must de-dup
	}
	lockEntry := Package{
		Name: "dup-pkg", Version: "1.0.0", Type: "python",
		Locations: []string{"/poetry.lock"},
	}
	// A different version and a different type share the name but are NOT the same
	// package, so the tighter key must keep them separate.
	otherVersion := &Package{Name: "dup-pkg", Version: "2.0.0", Type: "python", Licenses: []License{{SPDXExpression: "MIT"}}}
	otherType := &Package{Name: "dup-pkg", Version: "1.0.0", Type: "npm", Licenses: []License{{SPDXExpression: "MIT"}}}

	// licensePackages mirrors GetLicenses' output: keyed by license, the same
	// package appears under each of its licenses.
	licensePackages := map[string][]*Package{
		"MIT":          {installed, otherVersion, otherType},
		"BSD-3-Clause": {bsd},
	}
	packagesNoLicenses := []Package{lockEntry}

	merged := mergeDuplicatePackages(licensePackages, packagesNoLicenses)

	byKey := make(map[string]*Package)
	for _, p := range merged {
		byKey[packageKey(p.Name, p.Version, p.Type)] = p
	}

	if len(byKey) != 3 {
		t.Fatalf("expected 3 distinct packages (python@1.0.0, python@2.0.0, npm@1.0.0), got %d: %+v", len(byKey), merged)
	}

	v1 := byKey[packageKey("dup-pkg", "1.0.0", "python")]
	if v1 == nil {
		t.Fatal("missing merged dup-pkg@1.0.0 (python)")
	}
	// licenses are unioned across all three entries
	if !licenseSlicesEqual(v1.Licenses, []License{{SPDXExpression: "MIT"}, {SPDXExpression: "BSD-3-Clause"}}) {
		t.Errorf("dup-pkg@1.0.0 should union its licenses, got %+v", v1.Licenses)
	}
	// locations are unioned and de-duplicated (the repeated dist-info path appears once)
	if !sameStringSet(v1.Locations, []string{"/site-packages/dup-pkg-1.0.0.dist-info/METADATA", "/poetry.lock"}) {
		t.Errorf("dup-pkg@1.0.0 should union locations without duplicates, got %+v", v1.Locations)
	}

	// a different version and a different type stay separate
	if byKey[packageKey("dup-pkg", "2.0.0", "python")] == nil {
		t.Error("dup-pkg@2.0.0 (python) should be kept as a distinct version")
	}
	if byKey[packageKey("dup-pkg", "1.0.0", "npm")] == nil {
		t.Error("dup-pkg@1.0.0 (npm) should not merge with the python package of the same name@version")
	}
}

// sameStringSet reports whether a and b contain the same elements, ignoring order.
func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]bool, len(a))
	for _, s := range a {
		seen[s] = true
	}
	for _, s := range b {
		if !seen[s] {
			return false
		}
	}
	return true
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
			Name:      grantPkg.Name,
			Version:   grantPkg.Version,
			Type:      pkg.Type(grantPkg.Type),
			Licenses:  pkg.NewLicenseSet(),
			Locations: locationsFromPaths(grantPkg.Locations),
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

// locationsFromPaths builds a syft LocationSet from a set of real paths.
func locationsFromPaths(paths []string) file.LocationSet {
	locations := make([]file.Location, 0, len(paths))
	for _, p := range paths {
		locations = append(locations, file.NewLocation(p))
	}
	return file.NewLocationSet(locations...)
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
