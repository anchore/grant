package grant

import (
	"fmt"
)

const reasonPackageIgnored = "package ignored per policy"

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

	// An SBOM can catalog the same package more than once: the same
	// version may appear with a license from one source and without a license from
	// another(syft gap). We merge those entries into a single package, unioning their licenses,
	// so each real package is evaluated and counted exactly once.
	for _, pkg := range mergeDuplicatePackages(licensePackages, packagesNoLicenses) {
		var packageResult PackageResult
		if len(pkg.Licenses) == 0 {
			packageResult = c.evaluatePackageNoLicense(pkg, policy)
		} else {
			packageResult = c.evaluatePackage(pkg, policy)
		}
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

// packageKey identifies a package for deduplication. Name, version, and type
// together distinguish a real package
func packageKey(name, version, pkgType string) string {
	return name + "@" + version + "@" + pkgType
}

// mergeDuplicatePackages collapses every cataloged entry for a given package
// (see packageKey) into a single package, unioning licenses and locations (each
// de-duplicated).
func mergeDuplicatePackages(licensePackages map[string][]*Package, packagesNoLicenses []Package) []*Package {
	order := make([]string, 0)
	merged := make(map[string]*Package)
	seenLicenses := make(map[string]map[string]bool)
	seenLocations := make(map[string]map[string]bool)

	add := func(pkg Package) {
		key := packageKey(pkg.Name, pkg.Version, pkg.Type)
		current, ok := merged[key]
		if !ok {
			clone := pkg
			clone.Licenses = make([]License, 0, len(pkg.Licenses))
			clone.Locations = make([]string, 0, len(pkg.Locations))
			merged[key] = &clone
			seenLicenses[key] = make(map[string]bool)
			seenLocations[key] = make(map[string]bool)
			order = append(order, key)
			current = &clone
		}
		for _, license := range pkg.Licenses {
			id := license.String()
			if seenLicenses[key][id] {
				continue
			}
			seenLicenses[key][id] = true
			current.Licenses = append(current.Licenses, license)
		}
		// Union locations too: the same package is often cataloged from several
		// sources (e.g. an installed dist-info and a lock file), each contributing
		// distinct evidence paths. Keeping them all preserves location evidence
		// without affecting the license decision.
		for _, location := range pkg.Locations {
			if seenLocations[key][location] {
				continue
			}
			seenLocations[key][location] = true
			current.Locations = append(current.Locations, location)
		}
	}

	for _, packages := range licensePackages {
		for _, pkg := range packages {
			add(*pkg)
		}
	}
	for _, pkg := range packagesNoLicenses {
		add(pkg)
	}

	unique := make([]*Package, 0, len(order))
	for _, key := range order {
		unique = append(unique, merged[key])
	}
	return unique
}

// evaluatePackage evaluates a single package with licenses against the policy
func (c *Case) evaluatePackage(pkg *Package, policy *Policy) PackageResult {
	// Check if package should be ignored
	if policy.IsPackageIgnored(pkg.Name) {
		return PackageResult{
			Package: *pkg,
			Reason:  reasonPackageIgnored,
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
			Reason:  reasonPackageIgnored,
		}
	}

	// Check if RequireLicense is enabled
	if policy.RequireLicense {
		// Deny packages without licenses when RequireLicense is true
		return PackageResult{
			Package: *pkg,
			Reason:  "package denied - no licenses found",
		}
	}

	// Allow packages without licenses when RequireLicense is false
	return PackageResult{
		Package: *pkg,
		Reason:  "package allowed - no license requirement",
	}
}

// categorizePackageResult adds the package result to the appropriate category
func (c *Case) categorizePackageResult(packageResult *PackageResult, result *EvaluationResult) {
	switch {
	case packageResult.Reason == reasonPackageIgnored:
		result.IgnoredPackages = append(result.IgnoredPackages, *packageResult)
	case len(packageResult.DeniedLicenses) > 0 || packageResult.Reason == "package denied - no licenses found":
		result.DeniedPackages = append(result.DeniedPackages, *packageResult)
	case packageResult.Reason == "package allowed - no license requirement":
		result.AllowedPackages = append(result.AllowedPackages, *packageResult)
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
