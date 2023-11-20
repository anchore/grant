package grant

import (
	"github.com/anchore/syft/syft/pkg"
)

type License struct {
	// SPDXExpression is the SPDX expression for the license
	SPDXExpression string `json:"spdxExpression"`
	// Name is the name of the individual license if SPDXExpression is unset
	Name string `json:"name"`
	// Value is contents of the license
	Value string `json:"value"`
	// Locations are the paths for a package that show evidence of the license
	Locations []string `json:"location"`
}

// ConvertSyftLicenses converts a syft LicenseSet to a grant License slice
func ConvertSyftLicenses(set pkg.LicenseSet) (licenses []License) {
	licenses = make([]License, 0)
	for _, lic := range set.ToSlice() {
		// get all the locations for the license
		locations := lic.Locations.ToSlice()
		licenseLocations := make([]string, 0)
		for _, location := range locations {
			licenseLocations = append(licenseLocations, location.RealPath)
		}

		if lic.SPDXExpression != "" {
			licenses = append(licenses, License{
				SPDXExpression: lic.SPDXExpression,
				Locations:      licenseLocations,
			})
			continue
		}

		// no spdx expression from syft so just add the license as-is
		// currently these are ignored by the checker
		licenses = append(licenses, License{
			Name:      lic.Value,
			Locations: licenseLocations,
		})
	}
	return licenses
}
