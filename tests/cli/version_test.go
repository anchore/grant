package cli

import "testing"

// main_test.go builds the grant binary that these tests invoke via runGrant.
func Test_VersionCommand(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		assertions []traitAssertion
	}{
		{
			name: "text output",
			args: []string{"--version"},
			assertions: []traitAssertion{
				assertInOutput("grant version"),
				assertSuccessfulReturnCode,
			},
		},
		{
			name: "long form",
			args: []string{"version"},
			assertions: []traitAssertion{
				assertInOutput("Application:"),
				assertInOutput("Version:"),
				assertInOutput("BuildDate:"),
				assertInOutput("GitCommit:"),
				assertInOutput("GitDescription:"),
				assertInOutput("Platform:"),
				assertInOutput("GoVersion:"),
				assertInOutput("Compiler:"),
				assertSuccessfulReturnCode,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, rc := runGrant(t, "", tt.args...)
			for _, assert := range tt.assertions {
				assert(t, stdout, stderr, rc)
			}
		})
	}
}
