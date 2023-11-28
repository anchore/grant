package grant

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/anchore/grant/internal/input"
	syftFormat "github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/sbom"
)

func Test_NewResult(t *testing.T) {
	tests := []struct {
		name      string
		policy    *Policy
		src       string
		want      Result
		cmpignore []cmp.Option
	}{
		{
			name:   "happy path",
			policy: DefaultPolicy(),
			src:    "fixtures/test.spdx.json",
			want: Result{
				Source:            "fixtures/test.spdx.json",
				Policy:            DefaultPolicy(),
				PackageViolations: make(map[string][]License),
				CompliantPackages: make(map[string][]License),
				IgnoredPackages:   make(map[string][]License),
				LicenseViolations: make(map[string][]Package),
				CompliantLicenses: make(map[string][]Package),
				IgnoredLicenses:   make(map[string][]Package),
			},
			cmpignore: []cmp.Option{
				cmpopts.IgnoreFields(Result{}, "sbom", "sbomFormat", "sbomFormatVersion"),
				cmpopts.IgnoreFields(Policy{}, "denyAll", "allowAll"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sb, formatID, version, err := generateSBOMFromFixture(tt.src)
			if err != nil {
				t.Fatalf("unable to generate sbom from fixture: %+v", err)
			}
			result := NewResult(tt.policy, tt.src, sb, formatID, version)
			if diff := cmp.Diff(tt.want, result, tt.cmpignore...); diff != "" {
				t.Errorf("NewResult() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_Result_Generate(t *testing.T) {
	tests := []struct {
		name                  string
		policy                *Policy
		src                   string
		expectedResultSummary ResultSummary
	}{
		{
			name:   "Result.Generate() denies all packages with licenses for the default policy",
			policy: DefaultPolicy(),
			src:    "fixtures/test.spdx.json",
			// cat grant/fixtures/test.spdx.json | jq '.packages | length'
			// 16 packages - 1 package with no licenses (alpine as the source is registered as a package) = 15 violations
			// TODO: currently the source container package is being dropped by the decoder, so we are not seeing it in the result
			expectedResultSummary: ResultSummary{
				CompliantPackages: 0,
				PackageViolations: 15,
				IgnoredPackages:   0,
				LicenseViolations: 7,
				CompliantLicenses: 0,
				IgnoredLicenses:   0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sb, formatID, version, err := generateSBOMFromFixture(tt.src)
			if err != nil {
				t.Fatalf("unable to generate sbom from fixture: %+v", err)
			}

			result := NewResult(tt.policy, tt.src, sb, formatID, version)
			err = result.Generate()
			if err != nil {
				t.Fatalf("unable to generate result: %+v", err)
			}
			gotResultSummary := result.Summary()
			if diff := cmp.Diff(tt.expectedResultSummary, gotResultSummary); diff != "" {
				t.Errorf("Result.Generate() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func generateSBOMFromFixture(fixture string) (sb *sbom.SBOM, formatID, version string, err error) {
	reader, err := input.GetReader(fixture)
	if err != nil {
		return nil, "", "", err
	}
	sbomDecoders := syftFormat.NewDecoderCollection(syftFormat.Decoders()...)
	sb, fID, version, err := sbomDecoders.Decode(reader)
	return sb, fID.String(), version, err
}
