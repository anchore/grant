package evalutation

import (
	"testing"

	"github.com/gobwas/glob"
	"github.com/google/go-cmp/cmp"

	"github.com/anchore/grant/grant"
)

func Test_NewLicenseEvaluations(t *testing.T) {
	tests := []struct {
		name        string
		config      EvaluationConfig
		caseFixture string
		wantFailed  bool
	}{
		{
			name:        "NewLicenseEvaluations returns a slice of LicenseEvaluation that fail for the DefaultPolicy",
			config:      DefaultEvaluationConfig(),
			caseFixture: "../../fixtures/multiple",
			wantFailed:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			grantCases := fixtureCase(tc.caseFixture)
			for _, c := range grantCases {
				caseEvaluations := NewLicenseEvaluations(tc.config, c)
				if len(caseEvaluations) == 0 {
					t.Fatal("could not build license evaluations")
				}
				//if len(caseEvaluations.Licenses()) == 0 {
				//	t.Fatal("could not build list of licenses from evaluations")
				//}
				if tc.wantFailed && !caseEvaluations.IsFailed() {
					t.Fatal("expected license evaluations to fail for default config")
				}
			}
		})
	}
}

func fixtureCase(fixturePath string) []grant.Case {
	return grant.NewCases(fixturePath)
}

func Test_checkLicense(t *testing.T) {
	tests := []struct {
		name    string
		config  EvaluationConfig
		license grant.License
		wants   struct {
			Pass    bool
			Reasons []Reason
		}
	}{
		{
			name:    "should reject denied licenses when SPDX expressions and CheckNON SPDX is False",
			license: grant.License{ID: "MIT", SPDXExpression: "MIT", LicenseID: "MIT"},
			// Only allow OSI licenses.
			config: EvaluationConfig{CheckNonSPDX: false, Policy: grant.DefaultPolicy().SetMatchNonSPDX(false)},
			wants: struct {
				Pass    bool
				Reasons []Reason
			}{
				Pass: false,
				Reasons: []Reason{{
					Detail:   ReasonLicenseDeniedPolicy,
					RuleName: "default-deny-all",
				}},
			},
		},
		{
			name:    "should reject denied licenses when CheckNonSPDX is also true",
			license: grant.License{Name: "foobar"},
			// Only allow OSI licenses.
			config: EvaluationConfig{CheckNonSPDX: true, Policy: grant.DefaultPolicy().SetMatchNonSPDX(true)},
			wants: struct {
				Pass    bool
				Reasons []Reason
			}{
				Pass: false,
				Reasons: []Reason{{
					Detail:   ReasonLicenseDeniedPolicy,
					RuleName: "default-deny-all",
				}},
			},
		},
		{
			name: "non-OSI approved licenses should be denied when EvaluationConfig.OsiApproved is true",
			license: grant.License{
				IsOsiApproved:  false,
				LicenseID:      "AGPL-1.0-only",
				SPDXExpression: "AGPL-1.0-only",
			},
			// Only allow OSI licenses.
			config: EvaluationConfig{OsiApproved: true},
			wants: struct {
				Pass    bool
				Reasons []Reason
			}{
				Pass: false,
				Reasons: []Reason{{
					Detail:   ReasonLicenseDeniedOSI,
					RuleName: RuleNameNotOSIApproved,
				}},
			},
		},
		{
			name: "non-OSI approved licenses should be allowed when it's not an SPDX expression",
			license: grant.License{
				IsOsiApproved: false,
				// Non-SPDX license
				Name: "AGPL-1.0-only",
			},
			// Only allow OSI licenses.
			config: EvaluationConfig{OsiApproved: true},
			wants: struct {
				Pass    bool
				Reasons []Reason
			}{
				Pass:    true,
				Reasons: []Reason{{Detail: ReasonLicenseAllowed}},
			},
		},
		{
			name: "non-OSI approved licenses should be allowed when EvaluationConfig.OsiApproved is false",
			license: grant.License{
				IsOsiApproved:  false,
				LicenseID:      "AGPL-1.0-only",
				SPDXExpression: "AGPL-1.0-only",
			},
			config: EvaluationConfig{},
			wants: struct {
				Pass    bool
				Reasons []Reason
			}{
				Pass:    true,
				Reasons: []Reason{{Detail: ReasonLicenseAllowed}},
			},
		},
		{
			// Verifies rules are evaluated from first to last.
			name:    "A 'Deny' rule preceding a 'Deny' rule should always take precedence",
			license: grant.License{LicenseID: "BSD-3-Clause", SPDXExpression: "BSD-3-Clause"},
			config: EvaluationConfig{
				Policy: grant.Policy{
					Rules: []grant.Rule{
						{
							Name:       "allow-bsd-licenses",
							Glob:       glob.MustCompile("bsd-*"),
							Exceptions: []glob.Glob{},
							Mode:       grant.Allow,
							Reason:     "BSD licenses are allowed",
						},
						{
							Name:       "deny-all",
							Glob:       glob.MustCompile("*"),
							Exceptions: []glob.Glob{},
							Mode:       grant.Deny,
							Reason:     "No 'Allow' rule matched, unknown licenses are not allowed.",
						},
					},
				},
			},
			wants: struct {
				Pass    bool
				Reasons []Reason
			}{
				Pass: true,
				Reasons: []Reason{{
					Detail:   ReasonLicenseAllowed,
					RuleName: "allow-bsd-licenses",
				}},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := checkLicense(tc.config, &grant.Package{}, tc.license)
			if tc.wants.Pass != result.Pass {
				t.Errorf("Expected Pass to be %t, got %t", tc.wants.Pass, result.Pass)
			}
			if diff := cmp.Diff(tc.license, result.License); diff != "" {
				t.Errorf("Mismatched 'License' field (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.config.Policy, result.Policy); diff != "" {
				t.Errorf("Mismatched 'Policy' field (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.wants.Reasons, result.Reason); diff != "" {
				t.Errorf("Mismatched 'Reasons' field (-want +got):\n%s", diff)
			}
		})
	}
}
