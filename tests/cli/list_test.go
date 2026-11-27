package cli

import "testing"

func TestListCmdTargetThatCannotBeLoaded(t *testing.T) {
	cfg := emptyConfig(t)

	tests := []struct {
		name       string
		args       []string
		stdin      string
		assertions []traitAssertion
	}{
		{
			name:  "valid SBOM exits zero",
			args:  []string{"-c", cfg, "list", "-"},
			stdin: testSBOM,
			assertions: []traitAssertion{
				assertInOutput("MIT"),
				assertSuccessfulReturnCode,
			},
		},
		{
			name:  "stdin that is not an SBOM exits non-zero and names the target",
			args:  []string{"-c", cfg, "list", "-"},
			stdin: "this is not an sbom",
			assertions: []traitAssertion{
				assertInOutput("unable to list licenses for: -"),
				assertFailingReturnCode,
			},
		},
		{
			name:  "json output still reports the error status and exits non-zero",
			args:  []string{"-c", cfg, "-o", "json", "list", "-"},
			stdin: "this is not an sbom",
			assertions: []traitAssertion{
				assertJSONReport,
				assertInOutput(`"status": "error"`),
				assertFailingReturnCode,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, rc := runGrant(t, tt.stdin, tt.args...)
			for _, assert := range tt.assertions {
				assert(t, stdout, stderr, rc)
			}
		})
	}
}
