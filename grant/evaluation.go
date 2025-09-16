package grant

import (
	"fmt"
)

// EvaluationResult represents the result of evaluating a Case against a Policy
type EvaluationResult struct {
	// AllowedPackages are packages that passed the policy evaluation
	AllowedPackages []PackageResult `json:"allowed_packages"`

	// DeniedPackages are packages that failed the policy evaluation
	DeniedPackages []PackageResult `json:"denied_packages"`

	// IgnoredPackages are packages that were ignored per policy
	IgnoredPackages []PackageResult `json:"ignored_packages"`

	// Summary provides high-level statistics
	Summary EvaluationSummary `json:"summary"`
}

// PackageResult represents the evaluation result for a single package
type PackageResult struct {
	Package Package `json:"package"`

	// AllowedLicenses are licenses that passed policy evaluation
	AllowedLicenses []License `json:"allowed_licenses,omitempty"`

	// DeniedLicenses are licenses that failed policy evaluation
	DeniedLicenses []License `json:"denied_licenses,omitempty"`

	// Reason explains why the package was allowed/denied/ignored
	Reason string `json:"reason"`
}

// EvaluationSummary provides high-level statistics about the evaluation
type EvaluationSummary struct {
	TotalPackages   int `json:"total_packages"`
	AllowedPackages int `json:"allowed_packages"`
	DeniedPackages  int `json:"denied_packages"`
	IgnoredPackages int `json:"ignored_packages"`
}

// Evaluate evaluates a Case against a Policy and returns the result
func (c *Case) Evaluate(policy *Policy) (*EvaluationResult, error) {
	if policy == nil {
		return nil, fmt.Errorf("policy cannot be nil")
	}

	result := &EvaluationResult{
		AllowedPackages: make([]PackageResult, 0),
		DeniedPackages:  make([]PackageResult, 0),
		IgnoredPackages: make([]PackageResult, 0),
	}

	// Get all licenses and packages from the case
	licensePackages, _, packagesNoLicenses := c.GetLicenses()

	// Collect all unique packages with licenses (avoid duplicates while preserving order)
	seenPackages := make(map[string]bool)
	var uniquePackages []*Package
	for _, packages := range licensePackages {
		for _, pkg := range packages {
			if !seenPackages[pkg.Name] {
				seenPackages[pkg.Name] = true
				uniquePackages = append(uniquePackages, pkg)
			}
		}
	}

	// Evaluate packages with licenses
	for _, pkg := range uniquePackages {
		packageResult := c.evaluatePackage(pkg, policy)
		c.categorizePackageResult(&packageResult, result)
	}

	// Evaluate packages without licenses (these are typically denied unless ignored)
	for _, pkg := range packagesNoLicenses {
		packageResult := c.evaluatePackageNoLicense(&pkg, policy)
		c.categorizePackageResult(&packageResult, result)
	}

	// Calculate summary
	result.Summary = EvaluationSummary{
		TotalPackages:   len(result.AllowedPackages) + len(result.DeniedPackages) + len(result.IgnoredPackages),
		AllowedPackages: len(result.AllowedPackages),
		DeniedPackages:  len(result.DeniedPackages),
		IgnoredPackages: len(result.IgnoredPackages),
	}

	return result, nil
}

// evaluatePackage evaluates a single package with licenses against the policy
func (c *Case) evaluatePackage(pkg *Package, policy *Policy) PackageResult {
	// Check if package should be ignored
	if policy.IsPackageIgnored(pkg.Name) {
		return PackageResult{
			Package: *pkg,
			Reason:  "package ignored per policy",
		}
	}

	// Categorize licenses
	var allowedLicenses []License
	var deniedLicenses []License
	var unknownLicenses []License

	for _, license := range pkg.Licenses {
		licenseStr := license.String()

		// Check if RequireKnownLicense is enabled and license is not SPDX
		switch {
		case policy.RequireKnownLicense && !license.IsSPDX():
			unknownLicenses = append(unknownLicenses, license)
			deniedLicenses = append(deniedLicenses, license)
		case policy.IsLicensePermitted(licenseStr):
			allowedLicenses = append(allowedLicenses, license)
		default:
			deniedLicenses = append(deniedLicenses, license)
		}
	}

	// Determine overall package result
	switch {
	case len(unknownLicenses) > 0:
		// If any license is unknown and RequireKnownLicense is true
		return PackageResult{
			Package:         *pkg,
			AllowedLicenses: allowedLicenses,
			DeniedLicenses:  deniedLicenses,
			Reason:          fmt.Sprintf("package denied due to %d unknown licenses", len(unknownLicenses)),
		}
	case len(deniedLicenses) > 0:
		// If any license is denied, the whole package is denied
		return PackageResult{
			Package:         *pkg,
			AllowedLicenses: allowedLicenses,
			DeniedLicenses:  deniedLicenses,
			Reason:          fmt.Sprintf("package denied due to %d denied licenses", len(deniedLicenses)),
		}
	case len(allowedLicenses) > 0:
		// All licenses are allowed
		return PackageResult{
			Package:         *pkg,
			AllowedLicenses: allowedLicenses,
			Reason:          "all licenses allowed",
		}
	default:
		// No licenses found (shouldn't happen in this path, but just in case)
		return PackageResult{
			Package: *pkg,
			Reason:  "no licenses found",
		}
	}
}

// evaluatePackageNoLicense evaluates a package that has no licenses
func (c *Case) evaluatePackageNoLicense(pkg *Package, policy *Policy) PackageResult {
	// Check if package should be ignored
	if policy.IsPackageIgnored(pkg.Name) {
		return PackageResult{
			Package: *pkg,
			Reason:  "package ignored per policy",
		}
	}

	// By default, deny packages without licenses (unless RequireLicense is explicitly set to false)
	// Since RequireLicense is a bool that defaults to false, we need to check if it's explicitly set
	// For now, we'll change the default behavior to deny packages without licenses
	return PackageResult{
		Package: *pkg,
		Reason:  "package denied - no licenses found",
	}
}

// categorizePackageResult adds the package result to the appropriate category
func (c *Case) categorizePackageResult(packageResult *PackageResult, result *EvaluationResult) {
	switch {
	case packageResult.Reason == "package ignored per policy":
		result.IgnoredPackages = append(result.IgnoredPackages, *packageResult)
	case len(packageResult.DeniedLicenses) > 0 || packageResult.Reason == "package denied - no licenses found":
		result.DeniedPackages = append(result.DeniedPackages, *packageResult)
	default:
		result.AllowedPackages = append(result.AllowedPackages, *packageResult)
	}
}

// HasDeniedPackages returns true if there are any denied packages
func (r *EvaluationResult) HasDeniedPackages() bool {
	return len(r.DeniedPackages) > 0
}

// IsCompliant returns true if all packages are either allowed or ignored (none denied)
func (r *EvaluationResult) IsCompliant() bool {
	return len(r.DeniedPackages) == 0
}
