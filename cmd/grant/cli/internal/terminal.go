package internal

import (
	"os"

	"golang.org/x/term"
)

// IsTerminalOutput returns true if stdout is a terminal (not piped or redirected)
func IsTerminalOutput() bool {
	return term.IsTerminal(int(os.Stdout.Fd())) // #nosec G115 -- file descriptors are safe to convert to int
}

// IsTerminalError returns true if stderr is a terminal (not piped or redirected)
func IsTerminalError() bool {
	return term.IsTerminal(int(os.Stderr.Fd())) // #nosec G115 -- file descriptors are safe to convert to int
}

// IsTerminalInput returns true if stdin is a terminal (not piped or redirected)
func IsTerminalInput() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) // #nosec G115 -- file descriptors are safe to convert to int
}

// TerminalWidth returns the width of the terminal attached to stdout, or 0 when
// stdout is not a terminal or the size cannot be determined. Callers use 0 to
// mean "leave the output alone", so redirected and piped output is unchanged.
func TerminalWidth() int {
	if !IsTerminalOutput() {
		return 0
	}

	width, _, err := term.GetSize(int(os.Stdout.Fd())) // #nosec G115 -- file descriptors are safe to convert to int
	if err != nil || width <= 0 {
		return 0
	}

	return width
}
