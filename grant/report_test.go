package grant

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func Test_NewReport(t *testing.T) {
	tests := []struct {
		name           string
		srcs           []string
		policy         *Policy
		want           *Report
		wantErr        bool
		compareOptions []cmp.Option
	}{
		{
			name:   "grant report constructor builds a new report, with the default policy, for a single source",
			srcs:   []string{"fixtures/test.spdx.json"},
			policy: DefaultPolicy(),
			want: &Report{
				Sources: []string{"fixtures/test.spdx.json"},
				Policy:  DefaultPolicy(),
				Results: []Result{
					{
						Source:            "fixtures/test.spdx.json",
						Policy:            DefaultPolicy(),
						PackageViolations: make(map[string][]License),
						CompliantPackages: make(map[string][]License),
						IgnoredPackages:   make(map[string][]License),
						LicenseViolations: make(map[string][]Package),
						CompliantLicenses: make(map[string][]Package),
						IgnoredLicenses:   make(map[string][]Package),
					},
				},
			},
			wantErr: false,
			compareOptions: []cmp.Option{
				cmpopts.IgnoreFields(Policy{}, "denyAll", "allowAll"),
				cmpopts.IgnoreFields(Report{}, "Timestamp", "errors"),
				cmpopts.IgnoreFields(Result{}, "sbom", "sbomFormat", "sbomFormatVersion"),
			},
		},
		{
			name:   "grant report constructor builds a new report, with the default policy, for multiple sources",
			srcs:   []string{"fixtures/test.spdx.json", "fixtures/alpine.spdx"},
			policy: DefaultPolicy(),
			want: &Report{
				Sources: []string{"fixtures/test.spdx.json", "fixtures/alpine.spdx"},
				Policy:  DefaultPolicy(),
				Results: []Result{
					{
						Source:            "fixtures/test.spdx.json",
						Policy:            DefaultPolicy(),
						PackageViolations: make(map[string][]License),
						CompliantPackages: make(map[string][]License),
						IgnoredPackages:   make(map[string][]License),
						LicenseViolations: make(map[string][]Package),
						CompliantLicenses: make(map[string][]Package),
						IgnoredLicenses:   make(map[string][]Package),
					},
					{
						Source:            "fixtures/alpine.spdx",
						Policy:            DefaultPolicy(),
						PackageViolations: make(map[string][]License),
						CompliantPackages: make(map[string][]License),
						IgnoredPackages:   make(map[string][]License),
						LicenseViolations: make(map[string][]Package),
						CompliantLicenses: make(map[string][]Package),
						IgnoredLicenses:   make(map[string][]Package),
					},
				},
			},
			wantErr: false,
			compareOptions: []cmp.Option{
				cmpopts.IgnoreFields(Policy{}, "denyAll", "allowAll"),
				cmpopts.IgnoreFields(Report{}, "Timestamp", "errors"),
				cmpopts.IgnoreFields(Result{}, "sbom", "sbomFormat", "sbomFormatVersion"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewReport(tt.policy, tt.srcs...)
			if got == nil {
				t.Errorf("NewReport() = %v, want %v", got, tt.want)
			}
			if diff := cmp.Diff(tt.want, got, tt.compareOptions...); diff != "" {
				t.Errorf("NewReport() mismatch (-want +got):\n%s", diff)
			}
			if len(got.errors) > 0 && !tt.wantErr {
				t.Errorf("NewReport() errors = %v, want %v", got.errors, nil)
			}
		})
	}
}
