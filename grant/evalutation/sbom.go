package evalutation

import (
	"github.com/anchore/grant/grant"
	"github.com/anchore/syft/syft/sbom"
)

func newSbomLicenseEvalIndex(ec EvaluationConfig, s sbom.SBOM) *sbomLicenseEvalIndex {
	index := evalIndex(ec.Policy)
	for pkg := range s.Artifacts.Packages.Enumerate() {
		// since we use syft as a library to generate the sbom we need to convert its packages/licenses to grant types
		grantPkg := convertSyftPackage(pkg)
		if len(grantPkg.Licenses) == 0 {
			// no licenses found for this package
			index.addCompliant(grantPkg, nil)
		}
		for _, license := range grantPkg.Licenses {
			// TODO: check if the license is in the config ignore list
			// TODO: check if the config wants us to check for non-SPDX licenses
			if !license.IsSPDX() {
				index.addIgnored(grantPkg, license)
				continue
			}

			if ec.Policy.IsDenied(license) {
				index.addViolation(grantPkg, license)
				continue
			}
			// otherwise, the license is allowed
			index.addCompliant(grantPkg, &license)
		}
	}

	return index
}

func evalIndex(p grant.Policy) *sbomLicenseEvalIndex {
	return &sbomLicenseEvalIndex{
		packages:          make(map[grant.PackageID]grant.Package),
		packageViolations: make(map[grant.PackageID][]grant.License),
		compliantPackages: make(map[grant.PackageID][]grant.License),
		ignoredPackages:   make(map[grant.PackageID][]grant.License),

		licenses:          make(map[grant.LicenseID]grant.License),
		licenseViolations: make(map[grant.LicenseID][]grant.Package),
		compliantLicenses: make(map[grant.LicenseID][]grant.Package),
		ignoredLicenses:   make(map[grant.LicenseID][]grant.Package),
		policy:            p,
	}
}

// sboms map packages and licenses together
// sbomLicenseEvalIndex is a more complex Evaluation that tracks packages and licenses
type sbomLicenseEvalIndex struct {
	licenses map[grant.LicenseID]grant.License

	// licenseViolations not allowed by the policy and the packages that contained them
	// The key for these is the all lowercase SPDX license ID found in internal/spdxlicense/license.go
	licenseViolations map[grant.LicenseID][]grant.Package
	// compliantLicenses that were allowed by the policy and the packages that contained them
	compliantLicenses map[grant.LicenseID][]grant.Package
	// ignoredLicenses that were not SPDX compliant and the packages that contained them
	ignoredLicenses map[grant.LicenseID][]grant.Package

	packages map[grant.PackageID]grant.Package

	// packageViolations and their licenses that violated the policy
	packageViolations map[grant.PackageID][]grant.License
	// compliantPackages and their licenses that were compliant to the policy
	compliantPackages map[grant.PackageID][]grant.License
	// ignoredPackages tracks packages with licenses that were not SPDX compliant
	ignoredPackages map[grant.PackageID][]grant.License

	// policy is the policy used to generate this evaluation
	policy grant.Policy
}

func (i *sbomLicenseEvalIndex) isFailed() bool {
	return len(i.licenseViolations) > 0
}

func (i *sbomLicenseEvalIndex) addViolation(grantPkg grant.Package, license grant.License) {
	if _, ok := i.packages[grantPkg.ID]; !ok {
		i.packages[grantPkg.ID] = grantPkg
	}
	if _, ok := i.licenses[license.ID]; !ok {
		i.licenses[license.ID] = license
	}

	i.packageViolations[grantPkg.ID] = append(i.packageViolations[grantPkg.ID], license)
	i.licenseViolations[license.ID] = append(i.licenseViolations[license.ID], grantPkg)
}

func (i *sbomLicenseEvalIndex) addCompliant(grantPkg grant.Package, license *grant.License) {
	i.packages[grantPkg.ID] = grantPkg
	if license != nil {
		i.licenses[license.ID] = *license
		i.compliantPackages[grantPkg.ID] = append(i.compliantPackages[grantPkg.ID], *license)
		i.compliantLicenses[license.ID] = append(i.compliantLicenses[license.ID], grantPkg)
		return
	}

	// no license was provided, so we'll just add the package
	if _, ok := i.compliantPackages[grantPkg.ID]; !ok {
		i.compliantPackages[grantPkg.ID] = make([]grant.License, 0)
	}
}

// Note: if a license has been ignored, it means the SPDX expression was invalid
// or the user config specified to ignore the specific license
func (i *sbomLicenseEvalIndex) addIgnored(grantPkg grant.Package, license grant.License) {
	return
}
