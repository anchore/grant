package grant

import (
	"testing"

	"github.com/gobwas/glob"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func Test_DefaultPolicy(t *testing.T) {
	tests := []struct {
		name           string
		want           Policy
		compareOptions []cmp.Option
	}{
		{
			name: "DefaultPolicy() returns the expected default policy",
			want: Policy{
				AllowLicenses: make([]glob.Glob, 0),
				DenyLicenses: []glob.Glob{
					glob.MustCompile("*"),
				},
				IgnoreLicenses: make([]glob.Glob, 0),
				denyAll:        true,
			},
			compareOptions: []cmp.Option{
				cmpopts.IgnoreFields(Policy{}, "denyAll", "allowAll"),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DefaultPolicy()
			if diff := cmp.Diff(tc.want, got, tc.compareOptions...); diff != "" {
				t.Errorf("DefaultPolicy() mismatch (-want +got):\n%s", diff)
			}
			if got.denyAll != true {
				t.Errorf("DefaultPolicy() denyAll = %v, want %v", got.denyAll, true)
			}
		})
	}
}

func Test_NewPolicy(t *testing.T) {
	tests := []struct {
		name           string
		allowLicenses  []string
		denyLicenses   []string
		ignoreLicenses []string
		want           Policy
		compareOptions []cmp.Option
		wantErr        bool
	}{
		{
			name:           "NewPolicy() returns the expected policy",
			allowLicenses:  []string{"MIT", "Apache-2.0"},
			denyLicenses:   []string{"GPL-3.0"},
			ignoreLicenses: make([]string, 0),
			want: Policy{
				AllowLicenses: []glob.Glob{
					glob.MustCompile("mit"),
					glob.MustCompile("apache-2.0"),
				},
				DenyLicenses: []glob.Glob{
					glob.MustCompile("gpl-3.0"),
				},
				IgnoreLicenses: make([]glob.Glob, 0),
			},
			compareOptions: []cmp.Option{
				cmpopts.IgnoreFields(Policy{}, "denyAll", "allowAll"),
			},
			wantErr: false,
		},
		{
			name:           "NewPolicy() returns the expected policy when allow and deny licenses are empty",
			allowLicenses:  []string{},
			denyLicenses:   []string{},
			ignoreLicenses: []string{},
			want: Policy{
				AllowLicenses: make([]glob.Glob, 0),
				DenyLicenses: []glob.Glob{
					glob.MustCompile("*"),
				},
				IgnoreLicenses: make([]glob.Glob, 0),
			},
			compareOptions: []cmp.Option{
				cmpopts.IgnoreFields(Policy{}, "denyAll", "allowAll"),
			},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewPolicy(tc.allowLicenses, tc.denyLicenses, tc.ignoreLicenses)
			if (err != nil) != tc.wantErr {
				t.Errorf("NewPolicy() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
			if diff := cmp.Diff(tc.want, got, tc.compareOptions...); diff != "" {
				t.Errorf("NewPolicy() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
