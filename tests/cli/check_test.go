package cli

import (
	"os/exec"
	"strings"
	"testing"
)

// testSBOM is a minimal CycloneDX SBOM with a single MIT-licensed package,
// useful for testing policy evaluation against the empty config (which denies all).
const testSBOM = `{"bomFormat":"CycloneDX","specVersion":"1.4","components":[{"type":"library","name":"test-pkg","version":"1.0.0","licenses":[{"license":{"id":"MIT"}}]}]}`

func Test_CheckCmd(t *testing.T) {
	tests := []struct {
		name             string
		args             []string
		stdin            string
		expectedInOutput []string
		wantExitZero     bool
	}{
		{
			name:  "check command will deny all on empty config",
			args:  []string{"-c", emptyConfigPath, "check", "-"},
			stdin: testSBOM,
			expectedInOutput: []string{
				"denied",
				"test-pkg",
			},
		},
		{
			name:  "dry-run suppresses violation exit code",
			args:  []string{"-c", emptyConfigPath, "check", "--dry-run", "-"},
			stdin: testSBOM,
			expectedInOutput: []string{
				"denied",
				"test-pkg",
			},
			wantExitZero: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(grantTmpPath, tt.args...)
			if tt.stdin != "" {
				cmd.Stdin = strings.NewReader(tt.stdin)
			}
			output, err := cmd.CombinedOutput()

			if tt.wantExitZero {
				if err != nil {
					t.Fatalf("expected exit code 0, got error: %s\noutput: %s", err, string(output))
				}
			} else {
				if err == nil {
					t.Fatalf("expected non-zero exit code, got exit 0\noutput: %s", string(output))
				}
				if !strings.Contains(err.Error(), "exit status 1") {
					t.Fatalf("expected exit status 1, got: %s\noutput: %s", err, string(output))
				}
			}

			for _, expected := range tt.expectedInOutput {
				if !strings.Contains(string(output), expected) {
					t.Errorf("expected %q to be in output, but it wasn't; output: %s", expected, string(output))
				}
			}
		})
	}
}

func Test_CheckCmdStdin(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		stdin        string
		wantErr      bool
		wantInOutput []string
		wantAbsent   []string
	}{
		{
			name:    "no args and no stdin shows helpful error",
			args:    []string{"check"},
			wantErr: true,
			wantInOutput: []string{
				"no target specified and no input available on stdin",
			},
		},
		{
			name:    "piped stdin with no args reads from stdin",
			args:    []string{"check"},
			stdin:   `{"bomFormat":"CycloneDX","specVersion":"1.4","components":[]}`,
			wantErr: false,
			wantAbsent: []string{
				"no target specified",
				"requires at least 1 arg",
			},
		},
		{
			name:    "explicit args are used even when stdin is available",
			args:    []string{"check", "../../grant/testdata/mit-license.txt"},
			stdin:   "this should be ignored",
			wantErr: false,
			wantAbsent: []string{
				"no target specified",
			},
		},
		{
			name:    "explicit dash reads from stdin",
			args:    []string{"check", "-"},
			stdin:   `{"bomFormat":"CycloneDX","specVersion":"1.4","components":[]}`,
			wantErr: false,
			wantAbsent: []string{
				"no target specified",
				"requires at least 1 arg",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(grantTmpPath, tt.args...)
			if tt.stdin != "" {
				cmd.Stdin = strings.NewReader(tt.stdin)
			}
			output, err := cmd.CombinedOutput()
			got := string(output)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("grant %s: got success, want error", strings.Join(tt.args, " "))
				}
			} else {
				// Allow exit status 1 (policy violations) but not other errors
				if err != nil && !strings.Contains(err.Error(), "exit status 1") {
					t.Fatalf("grant %s: got unexpected error: %v\noutput: %s", strings.Join(tt.args, " "), err, got)
				}
			}

			for _, want := range tt.wantInOutput {
				if !strings.Contains(got, want) {
					t.Errorf("grant %s: output does not contain %q\ngot: %s", strings.Join(tt.args, " "), want, got)
				}
			}
			for _, absent := range tt.wantAbsent {
				if strings.Contains(got, absent) {
					t.Errorf("grant %s: output unexpectedly contains %q\ngot: %s", strings.Join(tt.args, " "), absent, got)
				}
			}
		})
	}
}
