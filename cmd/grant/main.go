package main

import (
	"os"

	"github.com/anchore/grant/cmd/grant/cli"
)

func main() {
	app := cli.Application()

	if err := app.Execute(); err != nil {
		os.Exit(1)
	}
}
