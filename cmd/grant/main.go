package main

import (
	"os"
	"runtime"

	"github.com/anchore/grant/cmd/grant/cli"
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
		os.Exit(1)
	}
}
