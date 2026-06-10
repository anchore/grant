package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testSBOM is a minimal CycloneDX SBOM with a single MIT-licensed package,
// useful for testing policy evaluation against the empty config (which denies all).
const testSBOM = `{"bomFormat":"CycloneDX","specVersion":"1.4","components":[{"type":"library","name":"test-pkg","version":"1.0.0","licenses":[{"license":{"id":"MIT"}}]}]}`

// dupComponentSBOM catalogs the same package twice at the same version: one entry
// carries a denied license (BSD) and the other carries no license at all. Under a
// policy that allows MIT and does not require a license, the license-less entry is
// allowed while the BSD entry is denied.
const dupComponentSBOM = `{"bomFormat":"CycloneDX","specVersion":"1.4","components":[` +
	`{"type":"library","name":"dup-pkg","version":"1.0.0","bom-ref":"a","licenses":[{"license":{"id":"BSD"}}]},` +
	`{"type":"library","name":"dup-pkg","version":"1.0.0","bom-ref":"b"}` +
	`]}`

func TestCheckCmd(t *testing.T) {
	cfg := emptyConfig(t)

	tests := []struct {
		name       string
		args       []string
		stdin      string
		assertions []traitAssertion
	}{
		{
			name:  "check command will deny all on empty config",
			args:  []string{"-c", cfg, "check", "-"},
			stdin: testSBOM,
			assertions: []traitAssertion{
				assertInOutput("denied"),
				assertInOutput("test-pkg"),
				assertFailingReturnCode,
			},
		},
		{
			name:  "dry-run suppresses violation exit code",
			args:  []string{"-c", cfg, "check", "--dry-run", "-"},
			stdin: testSBOM,
			assertions: []traitAssertion{
				assertInOutput("denied"),
				assertInOutput("test-pkg"),
				assertSuccessfulReturnCode,
			},
		},
		{
			name:       "quiet with violations exits non-zero",
			args:       []string{"-c", cfg, "-q", "check", "-"},
			stdin:      testSBOM,
			assertions: []traitAssertion{assertFailingReturnCode},
		},
		{
			name:       "quiet dry-run with violations exits zero",
			args:       []string{"-c", cfg, "-q", "check", "--dry-run", "-"},
			stdin:      testSBOM,
			assertions: []traitAssertion{assertSuccessfulReturnCode},
		},
		{
			name:  "summary with violations exits non-zero",
			args:  []string{"-c", cfg, "check", "--summary", "-"},
			stdin: testSBOM,
			assertions: []traitAssertion{
				assertInOutput("Non-compliant"),
				assertFailingReturnCode,
			},
		},
		{
			name:  "summary dry-run with violations exits zero",
			args:  []string{"-c", cfg, "check", "--summary", "--dry-run", "-"},
			stdin: testSBOM,
			assertions: []traitAssertion{
				assertInOutput("Non-compliant"),
				assertSuccessfulReturnCode,
			},
		},
		{
			name:       "json output with violations exits non-zero",
			args:       []string{"-c", cfg, "-o", "json", "check", "-"},
			stdin:      testSBOM,
			assertions: []traitAssertion{assertJSONReport, assertFailingReturnCode},
		},
		{
			name:       "json dry-run with violations exits zero",
			args:       []string{"-c", cfg, "-o", "json", "check", "--dry-run", "-"},
			stdin:      testSBOM,
			assertions: []traitAssertion{assertJSONReport, assertSuccessfulReturnCode},
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

func TestCheckCmdDeniedPackageDisplayed(t *testing.T) {
	// allow MIT and do not require a license, so the license-less duplicate is
	// allowed while the BSD entry is denied.
	config := writeConfig(t, "allow:\n  - MIT\nrequire-license: false\n")

	tests := []struct {
		name       string
		args       []string
		assertions []traitAssertion
	}{
		{
			name: "table output shows the denied package",
			args: []string{"-c", config, "check", "-"},
			assertions: []traitAssertion{
				assertInOutput("dup-pkg"),
				assertInOutput("1 denied"),
				assertNotInOutput("No denied packages found."),
				assertFailingReturnCode,
			},
		},
		{
			name: "json output marks the package denied",
			args: []string{"-c", config, "-o", "json", "check", "-"},
			assertions: []traitAssertion{
				assertJSONReport,
				assertInOutput("dup-pkg"),
				assertInOutput(`"decision": "deny"`),
				assertInOutput(`"denied": 1`),
				assertInOutput(`"status": "noncompliant"`),
				assertFailingReturnCode,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, rc := runGrant(t, dupComponentSBOM, tt.args...)
			for _, assert := range tt.assertions {
				assert(t, stdout, stderr, rc)
			}
		})
	}
}

// TestCheckCmdOutputFile verifies that JSON terminal output is suppressed
// when --output-file is set (since the same JSON is already written to the
// file), while table format continues to render on the terminal.
func TestCheckCmdOutputFile(t *testing.T) {
	tests := []struct {
		name        string
		globalFlags []string // flags placed before "check"
		checkFlags  []string // flags placed after "check"
		assertions  []traitAssertion
		wantInFile  []string // strings that should appear in the output file
	}{
		{
			name:        "json format writes to file only",
			globalFlags: []string{"-o", "json"},
			assertions:  []traitAssertion{assertNotInOutput("findings"), assertFailingReturnCode},
			wantInFile:  []string{"findings", "test-pkg"},
		},
		{
			name:        "json format dry-run writes to file only",
			globalFlags: []string{"-o", "json"},
			checkFlags:  []string{"--dry-run"},
			assertions:  []traitAssertion{assertNotInOutput("findings"), assertSuccessfulReturnCode},
			wantInFile:  []string{"findings", "test-pkg"},
		},
		{
			name:        "table format shows table and writes file",
			globalFlags: []string{"-o", "table"},
			assertions:  []traitAssertion{assertInOutput("test-pkg"), assertNotInOutput("findings"), assertFailingReturnCode},
			wantInFile:  []string{"findings"},
		},
		{
			name:        "table format dry-run shows table and writes file",
			globalFlags: []string{"-o", "table"},
			checkFlags:  []string{"--dry-run"},
			assertions:  []traitAssertion{assertInOutput("test-pkg"), assertNotInOutput("findings"), assertSuccessfulReturnCode},
			wantInFile:  []string{"findings"},
		},
		{
			name:        "json format with summary writes to file only",
			globalFlags: []string{"-o", "json"},
			checkFlags:  []string{"--summary"},
			assertions:  []traitAssertion{assertNotInOutput("findings"), assertFailingReturnCode},
			wantInFile:  []string{"findings"},
		},
		{
			name:        "table format with summary shows summary and writes file",
			globalFlags: []string{"-o", "table"},
			checkFlags:  []string{"--summary"},
			assertions:  []traitAssertion{assertInOutput("Non-compliant"), assertNotInOutput("findings"), assertFailingReturnCode},
			wantInFile:  []string{"findings"},
		},
		{
			name:        "json format with unlicensed writes to file only",
			globalFlags: []string{"-o", "json"},
			checkFlags:  []string{"--unlicensed"},
			assertions:  []traitAssertion{assertNotInOutput("findings"), assertFailingReturnCode},
			wantInFile:  []string{"findings"},
		},
		{
			name:        "table format with unlicensed shows table and writes file",
			globalFlags: []string{"-o", "table"},
			checkFlags:  []string{"--unlicensed"},
			assertions:  []traitAssertion{assertInOutput("packages without licenses"), assertNotInOutput("findings"), assertFailingReturnCode},
			wantInFile:  []string{"findings"},
		},
	}
	cfg := emptyConfig(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outFile := filepath.Join(t.TempDir(), "out.json")

			args := append([]string{"-c", cfg}, tt.globalFlags...)
			args = append(args, "--output-file", outFile)
			args = append(args, "check")
			args = append(args, tt.checkFlags...)
			args = append(args, "-")

			stdout, stderr, rc := runGrant(t, testSBOM, args...)
			for _, assert := range tt.assertions {
				assert(t, stdout, stderr, rc)
			}

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
	emptyComponentsSBOM := `{"bomFormat":"CycloneDX","specVersion":"1.4","components":[]}`

	tests := []struct {
		name       string
		args       []string
		stdin      string
		assertions []traitAssertion
	}{
		{
			name:  "no args and no stdin shows helpful error",
			args:  []string{"check"},
			stdin: "",
			assertions: []traitAssertion{
				assertInOutput("no target specified and no input available on stdin"),
				assertFailingReturnCode,
			},
		},
		{
			name:  "piped stdin with no args reads from stdin",
			args:  []string{"check"},
			stdin: emptyComponentsSBOM,
			assertions: []traitAssertion{
				assertNotInOutput("no target specified"),
				assertNotInOutput("requires at least 1 arg"),
			},
		},
		{
			name:  "explicit args are used even when stdin is available",
			args:  []string{"check", "../../grant/testdata/mit-license.txt"},
			stdin: "this should be ignored",
			assertions: []traitAssertion{
				assertNotInOutput("no target specified"),
			},
		},
		{
			name:  "explicit dash reads from stdin",
			args:  []string{"check", "-"},
			stdin: emptyComponentsSBOM,
			assertions: []traitAssertion{
				assertNotInOutput("no target specified"),
				assertNotInOutput("requires at least 1 arg"),
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
