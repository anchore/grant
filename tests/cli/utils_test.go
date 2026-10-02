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

	"github.com/stretchr/testify/require"
)

// grantBinaryEnvKey is the absolute path to a prebuilt grant binary. When set
// (for example by CI after a snapshot build) it is reused; otherwise the binary
// is built once on first use and the path is memoized here. This mirrors the
// syft/grype CLI suites, which build lazily rather than via a TestMain.
const grantBinaryEnvKey = "GRANT_BINARY_LOCATION"

// commandTimeout bounds a single grant invocation so a hung process cannot wedge
// the suite.
const commandTimeout = 60 * time.Second

// grantBinaryLocation returns the path to the grant binary under test
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
	require.NoError(tb, cmd.Run(), "failed to build grant")
}

func repoRoot(tb testing.TB) string {
	tb.Helper()
	root, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	require.NoError(tb, err, "unable to find repo root")
	absRoot, err := filepath.Abs(strings.TrimSpace(string(root)))
	require.NoError(tb, err, "unable to resolve repo root")
	return absRoot
}

// runGrant invokes the grant binary under test with the given stdin and
// arguments, returning stdout, stderr, and the process exit code separately
func runGrant(t testing.TB, stdin string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()

	cmd := exec.Command(grantBinaryLocation(t), args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	require.NoError(t, cmd.Start(), "failed to start grant")

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
	case <-time.After(commandTimeout):
		_ = cmd.Process.Kill()
		t.Fatalf("grant timed out after %s (args: %v)", commandTimeout, args)
	}

	return outBuf.String(), errBuf.String(), cmd.ProcessState.ExitCode()
}

// writeConfig writes a policy file into a temp dir and returns its path.
func writeConfig(t testing.TB, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "grant.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600), "failed to write config")
	return path
}

// emptyConfig writes an empty policy file, which denies every license.
func emptyConfig(t testing.TB) string {
	t.Helper()
	return writeConfig(t, "")
}
