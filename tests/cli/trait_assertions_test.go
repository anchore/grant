package cli

import (
	"encoding/json"
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// traitAssertion makes a single claim about a grant invocation's stdout, stderr,
// and exit code
type traitAssertion func(tb testing.TB, stdout, stderr string, exitCode int)

// ansiEscape matches the SGR color/style codes and OSC-8 hyperlink sequences that
// grant emits even when its output is not a terminal. Stripping them lets output
// assertions match the underlying text regardless of styling.
var ansiEscape = regexp.MustCompile("\x1b\\[[0-9;]*[a-zA-Z]|\x1b\\]8;;[^\x07\x1b]*(?:\x07|\x1b\\\\)")

func stripANSI(s string) string {
	return ansiEscape.ReplaceAllString(s, "")
}

func TestStripANSI(t *testing.T) {
	// SGR color, cursor movement, and an OSC-8 hyperlink — all of which grant emits.
	const in = "\x1b[36m⠋\x1b[0m \x1b[1A\x1b[2KName \x1b]8;;https://spdx.org/licenses/MIT.html\x1b\\MIT\x1b]8;;\x1b\\ done"
	const want = "⠋ Name MIT done"
	assert.Equal(t, want, stripANSI(in))
}

// combinedOutput returns stdout and stderr with styling stripped, joined so an
// assertion can look for text in either stream.
func combinedOutput(stdout, stderr string) string {
	return stripANSI(stdout) + "\n" + stripANSI(stderr)
}

// assertInOutput asserts that data appears in stdout or stderr.
func assertInOutput(data string) traitAssertion {
	return func(tb testing.TB, stdout, stderr string, _ int) {
		tb.Helper()
		assert.Contains(tb, combinedOutput(stdout, stderr), data)
	}
}

// assertNotInOutput asserts that data appears in neither stdout nor stderr.
func assertNotInOutput(data string) traitAssertion {
	return func(tb testing.TB, stdout, stderr string, _ int) {
		tb.Helper()
		assert.NotContains(tb, combinedOutput(stdout, stderr), data)
	}
}

// assertFileOutput reads the file at path and runs the given assertions against
// its contents (treated as stdout). It mirrors syft's helper for asserting on a
// report written via --output-file.
func assertFileOutput(path string, assertions ...traitAssertion) traitAssertion {
	return func(tb testing.TB, _, stderr string, exitCode int) {
		tb.Helper()
		content, err := os.ReadFile(path)
		require.NoErrorf(tb, err, "failed to read output file %q", path)
		for _, assertion := range assertions {
			assertion(tb, string(content), stderr, exitCode)
		}
	}
}

// assertFailingReturnCode asserts a non-zero exit code (a policy violation or error).
func assertFailingReturnCode(tb testing.TB, _, _ string, exitCode int) {
	tb.Helper()
	assert.NotZero(tb, exitCode, "expected a non-zero exit code")
}

// assertSuccessfulReturnCode asserts an exit code of 0.
func assertSuccessfulReturnCode(tb testing.TB, _, _ string, exitCode int) {
	tb.Helper()
	assert.Zero(tb, exitCode, "expected a zero exit code")
}

// assertJSONReport asserts that stdout is a single well-formed JSON document.
func assertJSONReport(tb testing.TB, stdout, _ string, _ int) {
	tb.Helper()
	var data any
	assert.NoErrorf(tb, json.Unmarshal([]byte(stdout), &data), "expected stdout to be valid JSON:\n%s", stdout)
}
