package cli

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// grantBinaryEnvKey is the absolute path to a prebuilt grant binary. When set
// (for example by CI after a snapshot build) it is reused; otherwise the binary
// is built once on first use and the path is memoized here. This mirrors the
// syft/grype CLI suites, which build lazily rather than via a TestMain.
const grantBinaryEnvKey = "GRANT_BINARY_LOCATION"

// grantBinaryLocation returns the path to the grant binary under test, building
// it on first use.
func grantBinaryLocation(tb testing.TB) string {
	tb.Helper()
	if loc := os.Getenv(grantBinaryEnvKey); loc != "" {
		return loc
	}
	loc := filepath.Join(repoRoot(tb), ".tmp", "grant")
	buildGrant(tb, loc)
	_ = os.Setenv(grantBinaryEnvKey, loc)
	return loc
}

func buildGrant(tb testing.TB, loc string) {
	tb.Helper()
	tb.Log("building grant...")
	cmd := exec.Command("go", "build", "-o", loc, "./cmd/grant")
	cmd.Dir = repoRoot(tb)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		tb.Fatalf("failed to build grant: %v", err)
	}
}

func repoRoot(tb testing.TB) string {
	tb.Helper()
	root, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		tb.Fatalf("unable to find repo root: %v", err)
	}
	absRoot, err := filepath.Abs(strings.TrimSpace(string(root)))
	if err != nil {
		tb.Fatalf("unable to resolve repo root: %v", err)
	}
	return absRoot
}

// runGrant invokes the grant binary under test with the given stdin and
// arguments, returning stdout, stderr, and the process exit code separately. A
// timeout aborts a hung process so a bad build cannot wedge the suite.
func runGrant(t testing.TB, stdin string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()

	cmd := exec.Command(grantBinaryLocation(t), args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start grant: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		var exitErr *exec.ExitError
		switch {
		case err == nil:
			// exit code 0
		case errors.As(err, &exitErr):
			return outBuf.String(), errBuf.String(), exitErr.ExitCode()
		default:
			t.Fatalf("failed to run grant: %v\nstderr: %s", err, errBuf.String())
		}
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("grant timed out after 60s (args: %v)", args)
	}

	return outBuf.String(), errBuf.String(), cmd.ProcessState.ExitCode()
}

// writeConfig writes a policy file into a temp dir and returns its path.
func writeConfig(t testing.TB, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "grant.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	return path
}

// emptyConfig writes an empty policy file, which denies every license.
func emptyConfig(t testing.TB) string {
	t.Helper()
	return writeConfig(t, "")
}
