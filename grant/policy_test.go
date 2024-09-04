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
						Name:       "default-deny-all",
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

func Test_Policy_IsDenied(t *testing.T) {
	tests := []struct {
		name string
		p    Policy
		want struct {
			denied bool
			rule   *Rule
		}
	}{
		{
			name: "Policy Default Deny All denies all licenses",
			p:    DefaultPolicy(),
			want: struct {
				denied bool
				rule   *Rule
			}{
				denied: true,
				rule: &Rule{
					Name:       "default-deny-all",
					Glob:       glob.MustCompile("*"),
					Exceptions: []glob.Glob{},
					Mode:       Deny,
					Reason:     "grant by default will deny all licenses",
				},
			},
		},

		{
			name: "Policy allowing all licenses",
			p: Policy{
				Rules: []Rule{{
					Name:       "allow-all",
					Glob:       glob.MustCompile("*"),
					Exceptions: []glob.Glob{},
					Mode:       Allow,
					Reason:     "all licenses are allowed",
				}},
			},
			want: struct {
				denied bool
				rule   *Rule
			}{
				denied: false,
				rule: &Rule{
					Name:       "allow-all",
					Glob:       glob.MustCompile("*"),
					Exceptions: []glob.Glob{},
					Mode:       Allow,
					Reason:     "all licenses are allowed",
				},
			},
		},
		{
			name: "Policy ignoring all licenses",
			p: Policy{
				Rules: []Rule{{
					Name:       "ignore-all",
					Glob:       glob.MustCompile("*"),
					Exceptions: []glob.Glob{},
					Mode:       Ignore,
					Reason:     "all licenses are ignored",
				}},
			},
			want: struct {
				denied bool
				rule   *Rule
			}{
				denied: false,
				rule: &Rule{
					Name:       "ignore-all",
					Glob:       glob.MustCompile("*"),
					Exceptions: []glob.Glob{},
					Mode:       Ignore,
					Reason:     "all licenses are ignored",
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			denied, rule := tc.p.IsDenied(License{LicenseID: "MIT", SPDXExpression: "MIT"}, nil)
			if denied != tc.want.denied {
				t.Errorf("Expected %t, got %t", tc.want.denied, denied)
			}
			if diff := cmp.Diff(tc.want.rule, rule); diff != "" {
				t.Errorf("IsDenied() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
