package grant

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func Test_ConvertSyftLicenses(t *testing.T) {
	singleSyftLicense := []pkg.License{
		pkg.License{
			SPDXExpression: "MIT",
			Value:          "MIT",
			Locations:      file.NewLocationSet(file.NewLocation("/foo/bar")),
		},
	}

	multipleLicensesDuplicate := []pkg.License{
		{
			SPDXExpression: "MIT",
			Value:          "MIT",
			Locations:      file.NewLocationSet(file.NewLocation("/foo/MIT")),
		},
		{
			SPDXExpression: "Apache-2.0 AND MIT",
			Value:          "Apache-2.0 AND MIT",
			Locations:      file.NewLocationSet(file.NewLocation("/foo/complex")),
		},
		{
			Value:     "I Made This License Up",
			Locations: file.NewLocationSet(file.NewLocation("/foo/custom")),
		},
	}

	tests := []struct {
		name string
		set  pkg.LicenseSet
		want []License
	}{
		{
			name: "grant converts a set with a single syft license to the expected grant license",
			set:  pkg.NewLicenseSet(singleSyftLicense...),
			want: []License{
				{
					SPDXExpression:  "MIT",
					Name:            "MIT License",
					Locations:       []string{"/foo/bar"},
					Reference:       "https://spdx.org/licenses/MIT.html",
					DetailsURL:      "https://spdx.org/licenses/MIT.json",
					ReferenceNumber: 246,
					LicenseID:       "MIT",
					SeeAlso:         []string{"https://opensource.org/licenses/MIT"},
					IsOsiApproved:   true,
				},
			},
		},
		{
			name: "grant converts a set with multiple syft licenses and a duplicate expression to the expected grant licenses",
			set:  pkg.NewLicenseSet(multipleLicensesDuplicate...),
			want: []License{
				{
					SPDXExpression:  "Apache-2.0",
					Name:            "Apache License 2.0",
					Locations:       []string{"/foo/complex"},
					Reference:       "https://spdx.org/licenses/Apache-2.0.html",
					DetailsURL:      "https://spdx.org/licenses/Apache-2.0.json",
					ReferenceNumber: 138,
					LicenseID:       "Apache-2.0",
					SeeAlso: []string{
						"https://www.apache.org/licenses/LICENSE-2.0",
						"https://opensource.org/licenses/Apache-2.0",
					},
					IsOsiApproved: true,
				},
				{
					SPDXExpression:  "MIT",
					Name:            "MIT License",
					Locations:       []string{"/foo/complex"},
					Reference:       "https://spdx.org/licenses/MIT.html",
					DetailsURL:      "https://spdx.org/licenses/MIT.json",
					ReferenceNumber: 246,
					LicenseID:       "MIT",
					SeeAlso:         []string{"https://opensource.org/licenses/MIT"},
					IsOsiApproved:   true,
				},
				{
					Name:      "I Made This License Up",
					Locations: []string{"/foo/custom"},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ConvertSyftLicenses(tc.set)
			if len(got) != len(tc.want) {
				t.Errorf("unexpected number of licenses: %d != %d", len(got), len(tc.want))
			}

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("unexpected licenses on convert (-want +got):\n%s", diff)
			}
		})
	}
}
