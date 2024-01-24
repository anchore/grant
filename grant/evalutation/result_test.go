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
		isFailed bool
	}{
		{
			name: "NewResults returns results from a group of cases that cannot pass the default config",
			ec:   DefaultEvaluationConfig(),
			fixtures: []string{
				"../../fixtures/multiple",
				"../../fixtures/licenses/MIT",
			},
			isFailed: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cases := grant.NewCases(tc.fixtures...)
			results := NewResults(tc.ec, cases...)
			if tc.isFailed != results.IsFailed() {
				t.Errorf("results.IsFailed() = %v, want %v", results.IsFailed(), tc.isFailed)
			}
		})
	}
}
