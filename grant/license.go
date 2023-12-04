package grant

type LicenseID string

// License is a grant license. Either SPDXExpression or Name will be set.
// If SPDXExpression is set, Name will be empty.
// Value is the contents of the license and is optional - can be fetched from the SPDX license list
// Locations are the relative paths for a license that show evidence of its detection.
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
