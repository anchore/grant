package grant

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildList_CountsEachPackageOnce(t *testing.T) {
	tests := []struct {
		name               string
		packages           []Package
		expectedTotal      int
		expectedUnlicensed int
		expectedNames      []string
	}{
		{
			// GetLicenses keys by license, so this package lands in two buckets.
			name: "two licenses on one package",
			packages: []Package{
				{Name: "multi", Version: "1.0.0", Licenses: []License{
					{SPDXExpression: "MIT"}, {SPDXExpression: "Apache-2.0"},
				}},
			},
			expectedTotal:      1,
			expectedUnlicensed: 0,
			expectedNames:      []string{"multi"},
		},
		{
			name: "one license each",
			packages: []Package{
				{Name: "a", Version: "1.0.0", Licenses: []License{{SPDXExpression: "MIT"}}},
				{Name: "b", Version: "1.0.0", Licenses: []License{{SPDXExpression: "Apache-2.0"}}},
			},
			expectedTotal:      2,
			expectedUnlicensed: 0,
			expectedNames:      []string{"a", "b"},
		},
		{
			name: "unlicensed package",
			packages: []Package{
				{Name: "bare", Version: "1.0.0", Licenses: []License{}},
			},
			expectedTotal:      1,
			expectedUnlicensed: 1,
			expectedNames:      []string{"bare"},
		},
		{
			name: "three licenses alongside an unlicensed package",
			packages: []Package{
				{Name: "multi", Version: "1.0.0", Licenses: []License{
					{SPDXExpression: "MIT"}, {SPDXExpression: "Apache-2.0"}, {SPDXExpression: "BSD-3-Clause"},
				}},
				{Name: "bare", Version: "1.0.0", Licenses: []License{}},
			},
			expectedTotal:      2,
			expectedUnlicensed: 1,
			expectedNames:      []string{"bare", "multi"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := createCaseFromPackages(tt.packages)

			licensePackages, licenses, packagesNoLicenses := c.GetLicenses()
			merged := mergeDuplicatePackages(licensePackages, packagesNoLicenses)
			findings := buildListFindings(merged)
			summary := buildListSummary(merged, licenses)

			assert.Equal(t, tt.expectedTotal, summary.Packages.Total, "summary total")
			assert.Equal(t, tt.expectedUnlicensed, summary.Packages.Unlicensed, "summary unlicensed")
			assert.Len(t, findings.Packages, tt.expectedTotal, "one finding per package")

			names := make([]string, 0, len(findings.Packages))
			for _, f := range findings.Packages {
				names = append(names, f.Name)
			}
			assert.ElementsMatch(t, tt.expectedNames, names)
		})
	}
}
