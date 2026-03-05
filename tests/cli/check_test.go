package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// testSBOM is a minimal CycloneDX SBOM with a single MIT-licensed package,
// useful for testing policy evaluation against the empty config (which denies all).
const testSBOM = `{"bomFormat":"CycloneDX","specVersion":"1.4","components":[{"type":"library","name":"test-pkg","version":"1.0.0","licenses":[{"license":{"id":"MIT"}}]}]}`

// assertCommandResult checks exit code and output content for a CLI invocation.
// Exit-code mismatches are fatal (no point checking output if the exit is wrong).
// Output containment mismatches use Errorf so all failures are reported.
func assertCommandResult(t *testing.T, got string, err error, wantFail bool, wantInOutput, wantAbsent []string) {
	t.Helper()

	if wantFail {
		if err == nil {
			t.Fatalf("got exit 0, want non-zero exit code\noutput: %s", got)
		}
		if !strings.Contains(err.Error(), "exit status 1") {
			t.Fatalf("got %s, want exit status 1\noutput: %s", err, got)
		}
	} else {
		if err != nil {
			t.Fatalf("got error %s, want exit 0\noutput: %s", err, got)
		}
	}

	for _, want := range wantInOutput {
		if !strings.Contains(got, want) {
			t.Errorf("output does not contain %q\ngot: %s", want, got)
		}
	}
	for _, absent := range wantAbsent {
		if strings.Contains(got, absent) {
			t.Errorf("output unexpectedly contains %q\ngot: %s", absent, got)
		}
	}
}

func TestCheckCmd(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		stdin        string
		wantInOutput []string
		wantAbsent   []string
		wantFail     bool
	}{
		{
			name:  "check command will deny all on empty config",
			args:  []string{"-c", emptyConfigPath, "check", "-"},
			stdin: testSBOM,
			wantInOutput: []string{
				"denied",
				"test-pkg",
			},
			wantFail: true,
		},
		{
			name:  "dry-run suppresses violation exit code",
			args:  []string{"-c", emptyConfigPath, "check", "--dry-run", "-"},
			stdin: testSBOM,
			wantInOutput: []string{
				"denied",
				"test-pkg",
			},
			wantFail: false,
		},
		{
			name:     "quiet with violations exits non-zero",
			args:     []string{"-c", emptyConfigPath, "-q", "check", "-"},
			stdin:    testSBOM,
			wantFail: true,
		},
		{
			name:     "quiet dry-run with violations exits zero",
			args:     []string{"-c", emptyConfigPath, "-q", "check", "--dry-run", "-"},
			stdin:    testSBOM,
			wantFail: false,
		},
		{
			name:  "summary with violations exits non-zero",
			args:  []string{"-c", emptyConfigPath, "check", "--summary", "-"},
			stdin: testSBOM,
			wantInOutput: []string{
				"Non-compliant",
			},
			wantFail: true,
		},
		{
			name:  "summary dry-run with violations exits zero",
			args:  []string{"-c", emptyConfigPath, "check", "--summary", "--dry-run", "-"},
			stdin: testSBOM,
			wantInOutput: []string{
				"Non-compliant",
			},
			wantFail: false,
		},
		{
			name:     "json output with violations exits non-zero",
			args:     []string{"-c", emptyConfigPath, "-o", "json", "check", "-"},
			stdin:    testSBOM,
			wantFail: true,
		},
		{
			name:     "json dry-run with violations exits zero",
			args:     []string{"-c", emptyConfigPath, "-o", "json", "check", "--dry-run", "-"},
			stdin:    testSBOM,
			wantFail: false,
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

			assertCommandResult(t, got, err, tt.wantFail, tt.wantInOutput, tt.wantAbsent)
		})
	}
}

// TestCheckCmdOutputFile verifies that JSON terminal output is suppressed
// when --output-file is set (since the same JSON is already written to the
// file), while table format continues to render on the terminal.
func TestCheckCmdOutputFile(t *testing.T) {
	tests := []struct {
		name         string
		globalFlags  []string // flags placed before "check"
		checkFlags   []string // flags placed after "check"
		wantFail     bool
		wantInOutput []string // strings that should appear in combined output
		wantAbsent   []string // strings that should NOT appear in combined output
		wantInFile   []string // strings that should appear in the output file
	}{
		{
			name:        "json format writes to file only",
			globalFlags: []string{"-o", "json"},
			wantFail:    true,
			wantAbsent:  []string{"findings"},
			wantInFile:  []string{"findings", "test-pkg"},
		},
		{
			name:        "json format dry-run writes to file only",
			globalFlags: []string{"-o", "json"},
			checkFlags:  []string{"--dry-run"},
			wantFail:    false,
			wantAbsent:  []string{"findings"},
			wantInFile:  []string{"findings", "test-pkg"},
		},
		{
			name:         "table format shows table and writes file",
			globalFlags:  []string{"-o", "table"},
			wantFail:     true,
			wantInOutput: []string{"test-pkg"},
			wantAbsent:   []string{"findings"},
			wantInFile:   []string{"findings"},
		},
		{
			name:         "table format dry-run shows table and writes file",
			globalFlags:  []string{"-o", "table"},
			checkFlags:   []string{"--dry-run"},
			wantFail:     false,
			wantInOutput: []string{"test-pkg"},
			wantAbsent:   []string{"findings"},
			wantInFile:   []string{"findings"},
		},
		{
			name:        "json format with summary writes to file only",
			globalFlags: []string{"-o", "json"},
			checkFlags:  []string{"--summary"},
			wantFail:    true,
			wantAbsent:  []string{"findings"},
			wantInFile:  []string{"findings"},
		},
		{
			name:         "table format with summary shows summary and writes file",
			globalFlags:  []string{"-o", "table"},
			checkFlags:   []string{"--summary"},
			wantFail:     true,
			wantInOutput: []string{"Non-compliant"},
			wantAbsent:   []string{"findings"},
			wantInFile:   []string{"findings"},
		},
		{
			name:        "json format with unlicensed writes to file only",
			globalFlags: []string{"-o", "json"},
			checkFlags:  []string{"--unlicensed"},
			wantFail:    true,
			wantAbsent:  []string{"findings"},
			wantInFile:  []string{"findings"},
		},
		{
			name:         "table format with unlicensed shows table and writes file",
			globalFlags:  []string{"-o", "table"},
			checkFlags:   []string{"--unlicensed"},
			wantFail:     true,
			wantInOutput: []string{"packages without licenses"},
			wantAbsent:   []string{"findings"},
			wantInFile:   []string{"findings"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outFile := filepath.Join(t.TempDir(), "out.json")

			args := append([]string{"-c", emptyConfigPath}, tt.globalFlags...)
			args = append(args, "--output-file", outFile)
			args = append(args, "check")
			args = append(args, tt.checkFlags...)
			args = append(args, "-")

			cmd := exec.Command(grantTmpPath, args...)
			cmd.Stdin = strings.NewReader(testSBOM)
			output, err := cmd.CombinedOutput()
			got := string(output)

			assertCommandResult(t, got, err, tt.wantFail, tt.wantInOutput, tt.wantAbsent)

			fileBytes, err := os.ReadFile(outFile)
			if err != nil {
				t.Fatalf("failed to read output file: %v", err)
			}
			fileContent := string(fileBytes)
			for _, want := range tt.wantInFile {
				if !strings.Contains(fileContent, want) {
					t.Errorf("output file does not contain %q\ngot: %s", want, fileContent)
				}
			}
		})
	}
}

func TestCheckCmdStdin(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		stdin        string
		wantFail     bool
		wantInOutput []string
		wantAbsent   []string
	}{
		{
			name:     "no args and no stdin shows helpful error",
			args:     []string{"check"},
			wantFail: true,
			wantInOutput: []string{
				"no target specified and no input available on stdin",
			},
		},
		{
			name:  "piped stdin with no args reads from stdin",
			args:  []string{"check"},
			stdin: `{"bomFormat":"CycloneDX","specVersion":"1.4","components":[]}`,
			wantAbsent: []string{
				"no target specified",
				"requires at least 1 arg",
			},
		},
		{
			name:  "explicit args are used even when stdin is available",
			args:  []string{"check", "../../grant/testdata/mit-license.txt"},
			stdin: "this should be ignored",
			wantAbsent: []string{
				"no target specified",
			},
		},
		{
			name:  "explicit dash reads from stdin",
			args:  []string{"check", "-"},
			stdin: `{"bomFormat":"CycloneDX","specVersion":"1.4","components":[]}`,
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

			if tt.wantFail {
				if err == nil {
					t.Fatalf("got exit 0, want non-zero exit code")
				}
			} else {
				// Allow exit status 1 (policy violations) but not other errors
				if err != nil && !strings.Contains(err.Error(), "exit status 1") {
					t.Fatalf("got unexpected error: %v\noutput: %s", err, got)
				}
			}

			for _, want := range tt.wantInOutput {
				if !strings.Contains(got, want) {
					t.Errorf("output does not contain %q\ngot: %s", want, got)
				}
			}
			for _, absent := range tt.wantAbsent {
				if strings.Contains(got, absent) {
					t.Errorf("output unexpectedly contains %q\ngot: %s", absent, got)
				}
			}
		})
	}
}
