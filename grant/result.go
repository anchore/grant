package grant

import (
	"github.com/anchore/syft/syft/sbom"
)

// Result is a single license policy evaluation for a single source
type Result struct {
	// Source that was checked
	Source string `json:"source" yaml:"source"`
	// Policy used against the Result
	Policy *Policy `json:"policy" yaml:"policy"`

	// PackageViolations and their licenses that violated the policy
	PackageViolations map[string][]License `json:"package_violations" yaml:"violations"`
	// CompliantPackages and their licenses that were compliant to the policy
	CompliantPackages map[string][]License `json:"compliant_packages" yaml:"compliant"`
	// IgnoredPackages tracks packages with licenses that were not SPDX compliant
	IgnoredPackages map[string][]License `json:"ignored_packages" yaml:"ignored"`

	// LicenseViolations not allowed by the policy and the packages that contained them
	// The key for these is the all lowercase SPDX license ID found in internal/spdxlicense/license.go
	LicenseViolations map[string][]Package `json:"license_violations" yaml:"license_violations"`
	// CompliantLicenses that were allowed by the policy and the packages that contained them
	CompliantLicenses map[string][]Package `json:"compliant_licenses" yaml:"license_compliant"`
	// IgnoredLicenses that were not SPDX compliant and the packages that contained them
	IgnoredLicenses map[string][]Package `json:"ignored_licenses" yaml:"license_ignored"`

	// The sbom that was analyzed to generate the report
	sbom              *sbom.SBOM
	sbomFormat        string
	sbomFormatVersion string
}

func NewResult(policy *Policy, src string, sbom *sbom.SBOM, formatID string, version string) Result {
	if policy == nil || policy.IsEmpty() {
		policy = DefaultPolicy()
	}

	return Result{
		Source:            src,
		Policy:            policy,
		PackageViolations: make(map[string][]License),
		CompliantPackages: make(map[string][]License),
		IgnoredPackages:   make(map[string][]License),
		LicenseViolations: make(map[string][]Package),
		CompliantLicenses: make(map[string][]Package),
		IgnoredLicenses:   make(map[string][]Package),

		sbom:              sbom,
		sbomFormat:        formatID,
		sbomFormatVersion: version,
	}
}

// Generate will fill in the Result with the violations, compliant, and ignored packages and licenses
func (r *Result) Generate() error {
	for pkg := range r.sbom.Artifacts.Packages.Enumerate() {
		// TODO: since we use syft to generate the sbom we need to convert packages/licenses to grant types
		// this feels like a code smell; we should consider a refactor where we use an interface so different sbom
		// providers can be plugged in where we can convert their licenses/packages to grant's types
		grantPkg := ConvertSyftPackage(pkg, r.Source)
		if len(grantPkg.Licenses) == 0 {
			// no licenses found for this package
			r.addCompliant(grantPkg, nil)
		}
		for _, license := range grantPkg.Licenses {
			// if the license is not SPDX compliant, ignore it
			// TODO: add a flag to allow non-SPDX compliant licenses to be checked against the policy
			if !license.IsSPDX() {
				r.addIgnored(grantPkg, license)
				continue
			}
			if r.Policy.Deny(license) {
				r.addViolation(grantPkg, license)
				continue
			}
			// otherwise, the license is allowed
			r.addCompliant(grantPkg, &license)
		}
	}
	return nil
}

type ResultSummary struct {
	CompliantPackages int `json:"compliant_packages" yaml:"compliant_packages"`
	PackageViolations int `json:"package_violations" yaml:"package_violations"`
	IgnoredPackages   int `json:"ignored_packages" yaml:"ignored_packages"`
	LicenseViolations int `json:"license_violations" yaml:"license_violations"`
	CompliantLicenses int `json:"compliant_licenses" yaml:"compliant_licenses"`
	IgnoredLicenses   int `json:"ignored_licenses" yaml:"ignored_licenses"`
}

func (r *Result) Summary() ResultSummary {
	return ResultSummary{
		CompliantPackages: len(r.CompliantPackages),
		PackageViolations: len(r.PackageViolations),
		IgnoredPackages:   len(r.IgnoredPackages),
		LicenseViolations: len(r.LicenseViolations),
		CompliantLicenses: len(r.CompliantLicenses),
		IgnoredLicenses:   len(r.IgnoredLicenses),
	}
}

func (r *Result) addViolation(grantPkg Package, license License) {
	r.PackageViolations[grantPkg.Name] = append(r.PackageViolations[grantPkg.Name], license)
	r.LicenseViolations[license.SPDXExpression] = append(r.LicenseViolations[license.SPDXExpression], grantPkg)
}

func (r *Result) addCompliant(grantPkg Package, license *License) {
	// a package with no licenses is compliant
	if license == nil {
		if _, ok := r.CompliantPackages[grantPkg.Name]; !ok {
			r.CompliantPackages[grantPkg.Name] = make([]License, 0)
		}
		// we already know this package is compliant and has been set from a previous call
		return
	}
	r.CompliantPackages[grantPkg.Name] = append(r.CompliantPackages[grantPkg.Name], *license)
	r.CompliantLicenses[license.SPDXExpression] = append(r.CompliantLicenses[license.SPDXExpression], grantPkg)
}

// Note: if a license has been ignored, it means the SPDX expression was invalid
// we track these by the license name, not the SPDX expression
func (r *Result) addIgnored(grantPkg Package, license License) {
	r.IgnoredPackages[grantPkg.Name] = append(r.IgnoredPackages[grantPkg.Name], license)
	r.IgnoredLicenses[license.Name] = append(r.IgnoredLicenses[license.Name], grantPkg)
}
