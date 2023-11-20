package spdxlicense

// SPDXLicenseResponse is the response from the SPDX license list endpoint
// https://spdx.org/licenses/licenses.json
type SPDXLicenseResponse struct {
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
