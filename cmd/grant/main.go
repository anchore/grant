package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/anchore/grant/cmd/grant/cli"
	"github.com/anchore/grant/cmd/grant/cli/command"
	"github.com/anchore/grant/internal"
)

var (
	version        = internal.NotProvided
	gitCommit      = internal.NotProvided
	buildDate      = internal.NotProvided
	gitDescription = internal.NotProvided
)

func main() {
	internal.SetBuildInfo(version, gitCommit, buildDate, gitDescription, runtime.Version())

	app := cli.Application()

	if err := app.Execute(); err != nil {
		if !errors.Is(err, command.ErrViolations) {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(1)
	}
}
