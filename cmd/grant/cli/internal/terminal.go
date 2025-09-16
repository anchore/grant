package internal

import (
	"os"

	"golang.org/x/term"
)

// IsTerminalOutput returns true if stdout is a terminal (not piped or redirected)
func IsTerminalOutput() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// IsTerminalError returns true if stderr is a terminal (not piped or redirected)
func IsTerminalError() bool {
	return term.IsTerminal(int(os.Stderr.Fd()))
}

// IsTerminalInput returns true if stdin is a terminal (not piped or redirected)
func IsTerminalInput() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}