package spdxlicense

import (
	"fmt"
	"strings"
)

// SPDXLicenseResponse is the response from the SPDX license list endpoint
// https://spdx.org/licenses/licenses.json
type Response struct {
	LicenseListVersion string        `json:"licenseListVersion"`
	ReleaseDate        string        `json:"releaseDate"`
	Licenses           []SPDXLicense `json:"licenses"`
}

type SPDXLicense struct {
	Reference             string   `json:"reference"`
	IsDeprecatedLicenseID bool     `json:"isDeprecatedLicenseId"`
	DetailsURL            string   `json:"detailsUrl"`
	ReferenceNumber       int      `json:"referenceNumber"`
	Name                  string   `json:"name"`
	LicenseID             string   `json:"licenseId"`
	SeeAlso               []string `json:"seeAlso"`
	IsOsiApproved         bool     `json:"isOsiApproved"`
}

func GetLicenseByID(id string) (license SPDXLicense, err error) {
	if index == nil {
		return license, fmt.Errorf("SPDX license index is nil")
	}

	license, ok := index[strings.ToLower(id)]
	if !ok {
		return license, fmt.Errorf("SPDX license %s not found", id)
	}

	return license, nil
}

func GetAllLicenseKeys() []string {
	if index == nil {
		return []string{}
	}
	
	keys := make([]string, 0, len(index))
	for k := range index {
		keys = append(keys, k)
	}
	return keys
}
