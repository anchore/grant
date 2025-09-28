package cli

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Note main_test.go is used to set up and teardown the tests. This is the entry point for testing and
// responsible for building the most recent version of the grant binary.
func Test_VersionCommand(t *testing.T) {
	tests := []struct {
		name             string
		command          string
		expectedInOutput []string
	}{
		{
			name:             "text output",
			command:          "--version",
			expectedInOutput: []string{"grant version"},
		},
		{
			name:    "long form",
			command: "version",
			expectedInOutput: []string{
				"Application:",
				"Version:",
				"BuildDate:",
				"GitCommit:",
				"GitDescription:",
				"Platform:",
				"GoVersion:",
				"Compiler:",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// check if the command is available
			cmd := exec.Command(grantTmpPath, test.command)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("command failed: %v: cmd output: %s", err, string(output))
			}

			for _, expected := range test.expectedInOutput {
				assert.Contains(t, string(output), expected, "expected output: %s not found in command output: %s", expected, string(output))
			}
		})
	}
}
