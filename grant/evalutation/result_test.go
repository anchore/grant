package evalutation

import (
	"testing"

	"github.com/anchore/grant/grant"
)

func Test_NewResults(t *testing.T) {
	tests := []struct {
		name     string
		ec       EvaluationConfig
		fixtures []string
		wantPass bool
	}{
		{
			name: "NewResults returns results from a group of cases that cannot pass the default config",
			ec:   DefaultEvaluationConfig(),
			fixtures: []string{
				"../../fixtures/multiple",
				"../../fixtures/licenses/MIT",
			},
			wantPass: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cases := grant.NewCases(&tc.ec.Policy, tc.fixtures...)
			results := NewResults(tc.ec, cases...)
			if tc.wantPass != results.Pass() {
				t.Errorf("NewResults() = %v, want %v", results.Pass(), tc.wantPass)
			}
		})
	}
}
