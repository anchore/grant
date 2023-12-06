package report

import (
	"github.com/github/go-spdx/v2/spdxexp"

	"github.com/anchore/grant/grant"
	"github.com/anchore/grant/internal/log"
	"github.com/anchore/grant/internal/spdxlicense"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

// sboms map packages and licenses together
// evalIndex is a more complex Evaluation that tracks packages and licenses
type evalIndex struct {
	packages map[grant.PackageID]grant.Package

	// packageViolations and their licenses that violated the policy
	packageViolations map[grant.PackageID][]grant.License `json:"package_violations" yaml:"violations"`
	// compliantPackages and their licenses that were compliant to the policy
	compliantPackages map[grant.PackageID][]grant.License `json:"compliant_packages" yaml:"compliant"`
	// ignoredPackages tracks packages with licenses that were not SPDX compliant
	ignoredPackages map[grant.PackageID][]grant.License `json:"ignored_packages" yaml:"ignored"`

	licenses map[grant.LicenseID]grant.License

	// licenseViolations not allowed by the policy and the packages that contained them
	// The key for these is the all lowercase SPDX license ID found in internal/spdxlicense/license.go
	licenseViolations map[grant.LicenseID][]grant.Package `json:"license_violations" yaml:"license_violations"`
	// compliantLicenses that were allowed by the policy and the packages that contained them
	compliantLicenses map[grant.LicenseID][]grant.Package `json:"compliant_licenses" yaml:"license_compliant"`
	// ignoredLicenses that were not SPDX compliant and the packages that contained them
	ignoredLicenses map[grant.LicenseID][]grant.Package `json:"ignored_licenses" yaml:"license_ignored"`

	// policy is the policy used to generate this evaluation
	policy grant.Policy
}

func (i *evalIndex) GetPackages() []grant.Package {
	packages := make([]grant.Package, 0)
	for _, pkg := range i.packages {
		packages = append(packages, pkg)
	}
	return packages
}

func (i *evalIndex) GetLicenses() []grant.License {
	licenses := make([]grant.License, 0)
	for _, license := range i.licenses {
		licenses = append(licenses, license)
	}
	return licenses
}

// GetViolations is oriented by licenseID
func (i *evalIndex) GetViolations() []Violation {
	violations := make([]Violation, 0)
	for licenseID, packages := range i.licenseViolations {
		license := i.licenses[licenseID]
		for _, pkg := range packages {
			violations = append(violations, Violation{
				License: license,
				Package: pkg,
			})
		}
	}
	return violations
}

func (i *evalIndex) GetPolicy() grant.Policy {
	return i.policy
}

func (i *evalIndex) IsFailed() bool {
	return len(i.licenseViolations) > 0
}

func newEvalIndex(p grant.Policy) *evalIndex {
	return &evalIndex{
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

func (i *evalIndex) addViolation(grantPkg grant.Package, license grant.License) {
}

func (i *evalIndex) addCompliant(grantPkg grant.Package, license *grant.License) {
}

// Note: if a license has been ignored, it means the SPDX expression was invalid
// or the user config specified to ignore the specific license
func (i *evalIndex) addIgnored(grantPkg grant.Package, license grant.License) {
}

func evalFromSBOM(ec EvaluationConfig, s sbom.SBOM) *evalIndex {
	index := newEvalIndex(ec.Policy)
	for pkg := range s.Artifacts.Packages.Enumerate() {
		// since we use syft to generate the sbom we need to convert packages/licenses to grant types
		grantPkg := convertSyftPackage(pkg)
		if len(grantPkg.Licenses) == 0 {
			// no licenses found for this package
			index.addCompliant(grantPkg, nil)
		}
		for _, license := range grantPkg.Licenses {
			// TODO: check if the license is in the ignore list
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

func convertSyftPackage(p syftPkg.Package) grant.Package {
	locations := p.Locations.ToSlice()
	packageLocations := make([]string, 0)
	for _, location := range locations {
		packageLocations = append(packageLocations, location.RealPath)
	}

	return grant.Package{
		Name:      p.Name,
		Version:   p.Version,
		Licenses:  convertSyftLicenses(p.Licenses),
		Locations: packageLocations,
	}
}

// convertSyftLicenses converts a syft LicenseSet to a grant License slice
// note: syft licenses can sometimes have complex SPDX expressions.
// Grant licenses break down these expressions into individual licenses.
// Because license expressions could potentially contain multiple licenses
// that are already represented in the syft license set we need to de-duplicate
// syft licenses have a "Value" field which is the name of the license
// given to an invalid SPDX expression; grant licenses store this field as "Name"
func convertSyftLicenses(set syftPkg.LicenseSet) (licenses []grant.License) {
	licenses = make([]grant.License, 0)
	checked := make(map[string]bool)
	for _, license := range set.ToSlice() {
		locations := license.Locations.ToSlice()
		licenseLocations := make([]string, 0)
		for _, location := range locations {
			licenseLocations = append(licenseLocations, location.RealPath)
		}

		if license.SPDXExpression != "" {
			licenses = handleSPDXLicense(license, licenses, licenseLocations, checked)
			continue
		}

		licenses = addNonSPDXLicense(licenses, license, licenseLocations)
	}
	return licenses
}

func handleSPDXLicense(license syftPkg.License, licenses []grant.License, licenseLocations []string, checked map[string]bool) []grant.License {
	extractedLicenses, err := spdxexp.ExtractLicenses(license.SPDXExpression)
	if err != nil {
		log.Errorf("unable to extract licenses from SPDX expression: %s", license.SPDXExpression)
		return addNonSPDXLicense(licenses, license, licenseLocations)
	}

	// process each extracted license from the SPDX expression
	for _, extractedLicense := range extractedLicenses {
		// prevent duplicates from being added when using SPDX expressions
		// EG: "MIT AND MIT" is valid, but we want to de-duplicate these
		if check(checked, extractedLicense) {
			continue
		}

		// we have what seems to be a valid SPDX license ID, let's try and get more info about it
		spdxLicense, err := spdxlicense.GetLicenseByID(extractedLicense)
		if err != nil {
			log.Errorf("unable to get license by ID: %s; no matching spdx id found", extractedLicense)
			// if we can't find a matching SPDX license, just add the license as-is
			// TODO: best matching against the spdx list index
			addNonSPDXLicense(licenses, license, licenseLocations)
			continue
		}

		licenses = append(licenses, grant.License{
			SPDXExpression:        extractedLicense,
			Name:                  spdxLicense.Name,
			Locations:             licenseLocations,
			Reference:             spdxLicense.Reference,
			IsDeprecatedLicenseID: spdxLicense.IsDeprecatedLicenseID,
			DetailsURL:            spdxLicense.DetailsURL,
			ReferenceNumber:       spdxLicense.ReferenceNumber,
			LicenseID:             spdxLicense.LicenseID,
			SeeAlso:               spdxLicense.SeeAlso,
			IsOsiApproved:         spdxLicense.IsOsiApproved,
		})
	}
	return licenses
}

func addNonSPDXLicense(licenses []grant.License, license syftPkg.License, locations []string) []grant.License {
	return append(licenses, grant.License{
		Name:      license.Value,
		Locations: locations,
	})
}

func check(checked map[string]bool, license string) bool {
	if _, ok := checked[license]; !ok {
		checked[license] = true
		return false
	}
	return true
}
