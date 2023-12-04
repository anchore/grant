package report

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/anchore/grant/grant"
)

func Test_NewReport(t *testing.T) {
	tests := []struct {
		name           string
		srcs           []string
		policy         grant.Policy
		format         Format
		want           *Report
		wantErr        bool
		compareOptions []cmp.Option
	}{
		{
			name:    "grant report constructor builds a new report, with the default policy, for a single source",
			srcs:    []string{"fixtures/test.spdx.json"},
			policy:  grant.DefaultPolicy(),
			format:  Table,
			want:    &Report{},
			wantErr: false,
			compareOptions: []cmp.Option{
				cmpopts.IgnoreFields(grant.Policy{}, "denyAll", "allowAll"),
				cmpopts.IgnoreFields(Report{}, "Timestamp", "errors"),
			},
		},
		{
			name:    "grant report constructor builds a new report, with the default policy, for multiple sources",
			srcs:    []string{"fixtures/test.spdx.json", "fixtures/alpine.spdx"},
			policy:  grant.DefaultPolicy(),
			format:  Table,
			want:    &Report{},
			wantErr: false,
			compareOptions: []cmp.Option{
				cmpopts.IgnoreFields(grant.Policy{}, "denyAll", "allowAll"),
				cmpopts.IgnoreFields(Report{}, "Timestamp", "errors"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewReport(tt.format, tt.policy, tt.srcs...)
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
