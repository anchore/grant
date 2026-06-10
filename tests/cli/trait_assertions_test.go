package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

// traitAssertion makes a single claim about a grant invocation's stdout, stderr,
// and exit code.
type traitAssertion func(tb testing.TB, stdout, stderr string, exitCode int)

// assertInOutput asserts that data appears in stdout or stderr.
func assertInOutput(data string) traitAssertion {
	return func(tb testing.TB, stdout, stderr string, _ int) {
		tb.Helper()
		if !strings.Contains(stdout, data) && !strings.Contains(stderr, data) {
			tb.Errorf("expected %q in output, but it was absent\nstdout:\n%s\nstderr:\n%s", data, stdout, stderr)
		}
	}
}

// assertNotInOutput asserts that data appears in neither stdout nor stderr.
func assertNotInOutput(data string) traitAssertion {
	return func(tb testing.TB, stdout, stderr string, _ int) {
		tb.Helper()
		if strings.Contains(stdout, data) || strings.Contains(stderr, data) {
			tb.Errorf("expected %q to be absent from output, but it was present\nstdout:\n%s\nstderr:\n%s", data, stdout, stderr)
		}
	}
}

// assertFailingReturnCode asserts a non-zero exit code (a policy violation or error).
func assertFailingReturnCode(tb testing.TB, _, _ string, exitCode int) {
	tb.Helper()
	if exitCode == 0 {
		tb.Errorf("expected a non-zero exit code, but got 0")
	}
}

// assertSuccessfulReturnCode asserts an exit code of 0.
func assertSuccessfulReturnCode(tb testing.TB, _, _ string, exitCode int) {
	tb.Helper()
	if exitCode != 0 {
		tb.Errorf("expected exit code 0, but got %d", exitCode)
	}
}

// assertJSONReport asserts that stdout is a single well-formed JSON document.
func assertJSONReport(tb testing.TB, stdout, _ string, _ int) {
	tb.Helper()
	var data any
	if err := json.Unmarshal([]byte(stdout), &data); err != nil {
		tb.Errorf("expected stdout to be valid JSON, but it was not: %v\nstdout:\n%s", err, stdout)
	}
}
