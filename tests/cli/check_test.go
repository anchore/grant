package cli

import (
	"os/exec"
	"strings"
	"testing"
)

func Test_CheckCmd(t *testing.T) {
	tests := []struct {
		name             string
		args             []string
		expectedInOutput []string
	}{
		{
			name: "check command will deny all on empty config",
			args: []string{"-c", emptyConfigPath, "check", "dir:../../."},
			expectedInOutput: []string{
				"check failed",
				"✗",           // Non-compliant indicator
				"DENIED",      // Shows denied packages
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(grantTmpPath, tt.args...)
			output, err := cmd.CombinedOutput()
			if err != nil && !strings.Contains(err.Error(), "exit status 1") {
				t.Fatalf("cmd.CombinedOutput() failed with %s\n %s", err, string(output))
			}
			for _, expected := range tt.expectedInOutput {
				if !strings.Contains(string(output), expected) {
					t.Errorf("expected %s to be in output, but it wasn't; output: %s", expected, string(output))
				}
			}
		})
	}
}
