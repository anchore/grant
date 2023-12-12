package evalutation

import (
	"testing"

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
			grantCases := fixtureCase(tc.config, tc.caseFixture)
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

func fixtureCase(ec EvaluationConfig, fixturePath string) []grant.Case {
	return grant.NewCases(ec.Policy, fixturePath)
}
