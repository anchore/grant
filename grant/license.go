package grant

import (
	"github.com/github/go-spdx/v2/spdxexp"

	"github.com/anchore/grant/internal/log"
	"github.com/anchore/grant/internal/spdxlicense"
	"github.com/anchore/syft/syft/pkg"
)

// License is a grant license. Either SPDXExpression or Name will be set. If SPDXExpression is set, Name will be empty.
// Value is the contents of the license and is optional. Locations are the paths for a package that show evidence of the license.
type License struct {
	// SPDXExpression is the SPDX expression for the license
	SPDXExpression string `json:"spdxExpression"`
	// Name is the name of the individual license if SPDXExpression is unset
	Name string `json:"name"`
	// Contents are the text of the license
	Contents string `json:"value"`
	// Locations are the paths for a package that show evidence of the license
	Locations []string `json:"location"`

	// These fields are lifted from the SPDX license list.
	// internal/spdxlicnse/license.go
	Reference             string   `json:"reference"`
	IsDeprecatedLicenseID bool     `json:"isDeprecatedLicenseId"`
	DetailsURL            string   `json:"detailsUrl"`
	ReferenceNumber       int      `json:"referenceNumber"`
	LicenseID             string   `json:"licenseId"`
	SeeAlso               []string `json:"seeAlso"`
	IsOsiApproved         bool     `json:"isOsiApproved"`
}

func (l License) String() string {
	if l.SPDXExpression != "" {
		return l.SPDXExpression
	}
	return l.Name
}

func (l License) IsSPDX() bool {
	return l.SPDXExpression != ""
}

// ConvertSyftLicenses converts a syft LicenseSet to a grant License slice
// note: syft licenses can sometimes have complex SPDX expressions
// grant licenses break down these expressions into a slice of licenses
// because license expressions could potentially contain multiple licenses
// that are already represented in the syft license set we need to de-duplicate
// syft licenses have a "Value" field that is the name of the license
// given an invalid SPDX expression; grant licenses refer to this as "Name"
func ConvertSyftLicenses(set pkg.LicenseSet) (licenses []License) {
	licenses = make([]License, 0)
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

func handleSPDXLicense(license pkg.License, licenses []License, licenseLocations []string, checked map[string]bool) []License {
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

		licenses = append(licenses, License{
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

func addNonSPDXLicense(licenses []License, license pkg.License, locations []string) []License {
	return append(licenses, License{
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
