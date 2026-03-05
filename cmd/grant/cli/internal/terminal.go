package internal

import (
	"os"

	"golang.org/x/term"
)

// IsTerminalOutput returns true if stdout is a terminal (not piped or redirected)
func IsTerminalOutput() bool {
	return term.IsTerminal(int(os.Stdout.Fd())) //nolint:gosec // file descriptors are small non-negative integers
}

// IsTerminalError returns true if stderr is a terminal (not piped or redirected)
func IsTerminalError() bool {
	return term.IsTerminal(int(os.Stderr.Fd())) //nolint:gosec // file descriptors are small non-negative integers
}

// IsTerminalInput returns true if stdin is a terminal (not piped or redirected)
func IsTerminalInput() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) //nolint:gosec // file descriptors are small non-negative integers
}
