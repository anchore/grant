package spdxlicense

import (
	"fmt"
	"strings"
)

// RiskCategory represents the risk level associated with a license
type RiskCategory string

const (
	// RiskCategoryHigh represents strong copyleft licenses that require derivative works to be licensed under the same terms
	RiskCategoryHigh RiskCategory = "Strong Copyleft (High Risk)"

	// RiskCategoryMedium represents weak copyleft licenses with limited copyleft requirements (e.g., file-level, library-level)
	RiskCategoryMedium RiskCategory = "Weak Copyleft (Medium Risk)"

	// RiskCategoryLow represents permissive licenses that allow proprietary use with minimal restrictions
	RiskCategoryLow RiskCategory = "Permissive (Low Risk)"

	// RiskCategoryUncategorized represents licenses that have not been categorized
	RiskCategoryUncategorized RiskCategory = ""
)

// String returns the string representation of the RiskCategory
func (r RiskCategory) String() string {
	return string(r)
}

// IsHigh returns true if this is a high risk category
func (r RiskCategory) IsHigh() bool {
	return r == RiskCategoryHigh
}

// IsMedium returns true if this is a medium risk category
func (r RiskCategory) IsMedium() bool {
	return r == RiskCategoryMedium
}

// IsLow returns true if this is a low risk category
func (r RiskCategory) IsLow() bool {
	return r == RiskCategoryLow
}

// IsUncategorized returns true if this license has not been categorized
func (r RiskCategory) IsUncategorized() bool {
	return r == RiskCategoryUncategorized
}

// SPDXLicenseResponse is the response from the SPDX license list endpoint
// https://spdx.org/licenses/licenses.json
type Response struct {
	LicenseListVersion string        `json:"licenseListVersion"`
	ReleaseDate        string        `json:"releaseDate"`
	Licenses           []SPDXLicense `json:"licenses"`
}

type SPDXLicense struct {
	Reference             string       `json:"reference"`
	IsDeprecatedLicenseID bool         `json:"isDeprecatedLicenseId"`
	DetailsURL            string       `json:"detailsUrl"`
	ReferenceNumber       int          `json:"referenceNumber"`
	Name                  string       `json:"name"`
	LicenseID             string       `json:"licenseId"`
	SeeAlso               []string     `json:"seeAlso"`
	IsOsiApproved         bool         `json:"isOsiApproved"`
	RiskCategory          RiskCategory `json:"riskCategory,omitempty"`
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
