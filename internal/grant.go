// Package internal provides core application constants and metadata.
package internal

import (
	"fmt"
	"runtime"
)

const (
	// ApplicationName is the name of the Grant application.
	ApplicationName = "grant"
	// NotProvided is the value used when a build variable was not provided
	NotProvided = "[not provided]"
)

var (
	// Version info populated at build time
	version        = NotProvided
	gitCommit      = NotProvided
	buildDate      = NotProvided
	gitDescription = NotProvided
	platform       = fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
	goVersion      = runtime.Version()
	compiler       = runtime.Compiler
)

// BuildInfo holds the application build details
type BuildInfo struct {
	Application    string
	Version        string
	BuildDate      string
	GitCommit      string
	GitDescription string
	Platform       string
	GoVersion      string
	Compiler       string
}

// SetBuildInfo sets build information from main package
func SetBuildInfo(ver, commit, date, desc, goVer string) {
	if ver != "" && ver != NotProvided {
		version = ver
	}
	if commit != "" && commit != NotProvided {
		gitCommit = commit
	}
	if date != "" && date != NotProvided {
		buildDate = date
	}
	if desc != "" && desc != NotProvided {
		gitDescription = desc
	}
	if goVer != "" {
		goVersion = goVer
	}
}

// GetBuildInfo returns the current build information
func GetBuildInfo() BuildInfo {
	return BuildInfo{
		Application:    ApplicationName,
		Version:        version,
		BuildDate:      buildDate,
		GitCommit:      gitCommit,
		GitDescription: gitDescription,
		Platform:       platform,
		GoVersion:      goVersion,
		Compiler:       compiler,
	}
}

// ApplicationVersion returns the current version for backward compatibility
var ApplicationVersion = func() string {
	if version != NotProvided {
		return version
	}
	return "0.0.1"
}()
