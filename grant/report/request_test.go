package report

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_determineRequest(t *testing.T) {
	tests := []struct {
		name            string
		userRequest     string
		expectedSBOM    int
		expectedLicense int
	}{
		{
			name:            "grant can determine a request for a single SBOM file",
			userRequest:     "../../fixtures/multiple/alpine.spdx.json",
			expectedSBOM:    1,
			expectedLicense: 0,
		},
		{
			name:            "grant can determine a request for a single license file",
			userRequest:     "../../fixtures/licenses/MIT",
			expectedSBOM:    0,
			expectedLicense: 1,
		},
		{
			name:            "grant can determine a request for a directory (multiple evaluation results)",
			userRequest:     "../../fixtures/multiple",
			expectedSBOM:    1,
			expectedLicense: 1,
		},
		{
			name:            "grant can determine a request for an archive (single sbom)",
			userRequest:     "../../fixtures/java.tar.gz",
			expectedSBOM:    1,
			expectedLicense: 0,
		},
		//{
		//	name: "grant can determine a request for a container image (single sbom)",
		//},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requestBreakdown, err := determineRequest(tt.userRequest)
			if !assert.NoError(t, err) {
				t.Fatalf("unexpected error: %+v", err)
			}

			if !assert.Equal(t, tt.expectedSBOM, len(requestBreakdown.sboms)) {
				t.Fatalf("unexpected number of SBOMs: %d", len(requestBreakdown.sboms))
			}

			if !assert.Equal(t, tt.expectedLicense, len(requestBreakdown.licenses)) {
				t.Fatalf("unexpected number of licenses: %d", len(requestBreakdown.licenses))
			}
		})
	}
}
