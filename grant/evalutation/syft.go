package evalutation

import (
	"strings"

	"github.com/github/go-spdx/v2/spdxexp"

	"github.com/anchore/grant/grant"
	"github.com/anchore/grant/internal/log"
	"github.com/anchore/grant/internal/spdxlicense"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func convertSyftPackage(p syftPkg.Package) *grant.Package {
	locations := p.Locations.ToSlice()
	packageLocations := make([]string, 0)
	for _, location := range locations {
		packageLocations = append(packageLocations, location.RealPath)
	}

	return &grant.Package{
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
		//log.Errorf("unable to extract licenses from SPDX expression: %s", license.SPDXExpression)
		return addNonSPDXLicense(licenses, license, licenseLocations)
	}

	// process each extracted license from the SPDX expression
	for _, extractedLicense := range extractedLicenses {
		extractedLicense = strings.TrimRight(extractedLicense, "+")
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
