package grant

import (
	"testing"

	"github.com/gobwas/glob"
	"github.com/google/go-cmp/cmp"
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
				Rules: []Rule{
					{
						Glob:       glob.MustCompile("*"),
						Exceptions: []glob.Glob{},
						Mode:       Deny,
						Reason:     "grant by default will deny all licenses",
					},
				},
				MatchNonSPDX: false,
			},
			compareOptions: []cmp.Option{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DefaultPolicy()
			if diff := cmp.Diff(tc.want, got, tc.compareOptions...); diff != "" {
				t.Errorf("DefaultPolicy() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_NewPolicy(t *testing.T) {
	tests := []struct {
		name           string
		want           Policy
		rules          []Rule
		matchNonSPDX   bool
		compareOptions []cmp.Option
		wantErr        bool
	}{
		{
			name: "NewPolicy() returns the expected policy with no rules",
			want: Policy{
				Rules:        Rules{DefaultDenyAll},
				MatchNonSPDX: false,
			},
			compareOptions: []cmp.Option{},
			wantErr:        false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewPolicy(tc.matchNonSPDX, tc.rules...)
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
