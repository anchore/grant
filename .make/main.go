package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	. "github.com/anchore/go-make"
	"github.com/anchore/go-make/config"
	"github.com/anchore/go-make/file"
	"github.com/anchore/go-make/lang"
	"github.com/anchore/go-make/run"
	"github.com/anchore/go-make/tasks/golint"
	"github.com/anchore/go-make/tasks/goreleaser"
	"github.com/anchore/go-make/tasks/gotest"
)

func main() {
	Makefile(
		// cherry-pick golint tasks: keep format/lint-fix, but skip the upstream
		// static-analysis (it runs `bouncer check ./...`). We have our own
		// static-analysis below that uses grant's self-check instead.
		// note: --tests=false matches the prior Taskfile.yaml behavior; revisit when tests are linter-clean.
		golint.FormatTask(),
		golint.LintFixTask(golint.SkipTests()),

		goreleaser.Tasks(),
		gotest.Tasks(
			// exclude integration tests under tests/ (run separately)
			gotest.ExcludeGlob("**/tests/**"),
			gotest.CoverageThreshold(8),
		),
		gotest.FixtureTasks().RunOn("unit"),

		staticAnalysisTask(),
		licenseValidationTask(),
		cliTestTasks(),
		installTestTasks(),

		generateTasks(),
		demoTask(),
	)
}

// cliTestTasks runs the end-to-end CLI tests under tests/cli (which the unit task excludes) against the
// snapshot binary. The snapshot is built only when missing: in CI it is downloaded from the snapshot job, and
// rebuilding would burn time and clobber it. The tests exec that binary, so -race would only instrument the test
// harness; cli:race-smoke covers the binary itself.
func cliTestTasks() Task {
	return Task{
		Name:        "cli",
		Description: "run CLI tests against the snapshot binary",
		RunsOn:      lang.List("test"),
		Run: func() {
			bin := snapshotBinPath()
			if !file.Exists(bin) {
				Log("snapshot binary not found at %s, building a single-target snapshot", bin)
				Run("make snapshot:single-target")
			}
			Log("testing binary: %s", bin)
			Run("go test -count=1 -timeout=15m ./tests/cli/...", run.Env("GRANT_BINARY_LOCATION", bin), run.Stdout(os.Stderr))
		},
		Tasks: []Task{
			{
				Name:        "cli:race-smoke",
				Description: "exercise the CLI with the race detector",
				RunsOn:      lang.List("cli"),
				Run: func() {
					if !raceEnabled() {
						Log("race detector disabled, skipping race smoke")
						return
					}
					// --dry-run keeps the exit code at 0 even though the fixture has denied licenses
					Run("go run -race ./cmd/grant check --dry-run fixtures/alpine.tagvalue.spdx", run.Stdout(os.Stderr))
				},
			},
		},
	}
}

// snapshotBinPath is where goreleaser writes the snapshot binary for the current OS and arch.
func snapshotBinPath() string {
	arch := runtime.GOARCH
	switch arch {
	case "amd64":
		arch = "amd64_v1"
	case "arm64":
		arch = "arm64_v8.0"
	}
	return filepath.Join(RootDir(), "snapshot", runtime.GOOS+"-build_"+runtime.GOOS+"_"+arch, "grant")
}

// raceEnabled defaults to on in CI (off on windows) and can be forced either way with RACE=true|false.
func raceEnabled() bool {
	if enabled, err := strconv.ParseBool(config.Env("RACE", "")); err == nil {
		return enabled
	}
	return config.CI && !config.Windows
}

// installTestTasks drives the install.sh test suite under tests/install (unit tests plus acceptance
// tests against real releases in docker, or locally on mac).
func installTestTasks() Task {
	return Task{
		Tasks: []Task{
			{
				Name:        "install-test",
				Description: "run install.sh unit and acceptance tests",
				Run: func() {
					file.InDir("tests/install", func() { Run("make") })
				},
			},
			{
				Name:        "install-test-cache-save",
				Description: "save install.sh test image cache",
				Run: func() {
					file.InDir("tests/install", func() { Run("make save") })
				},
			},
			{
				Name:        "install-test-cache-load",
				Description: "load install.sh test image cache",
				Run: func() {
					file.InDir("tests/install", func() { Run("make load") })
				},
			},
			{
				Name:        "install-test-ci-mac",
				Description: "run install.sh unit and acceptance tests on mac (CI)",
				Run: func() {
					file.InDir("tests/install", func() { Run("make ci-test-mac") })
				},
			},
		},
	}
}

// staticAnalysisTask mirrors golint.StaticAnalysisTask but drops the
// `bouncer check` call — grant dogfoods its own license check via the
// license-validations task that hooks into this one via RunsOn.
//
// TODO: replace me with the standard golint.Tasks() later when go-make uses grant directly
func staticAnalysisTask() Task {
	return Task{
		Name:        "static-analysis",
		Description: "run lint checks",
		RunsOn:      lang.List("default"),
		Run: func() {
			Run("go mod tidy -diff")
			Run("golangci-lint run --tests=false")
			lang.Throw(findMalformedFilenames("."))
		},
	}
}

// licenseValidationTask runs grant against an SBOM of this repo to ensure all
// dependencies have allowable licenses. Hooks into static-analysis.
//
// note: we run syft and grant in separate Run() calls (rather than via a single
// `bash -c "syft … | grant …"`) so go-make's binny-managed tool resolution
// applies to each tool. The SBOM is piped through an in-memory buffer.
func licenseValidationTask() Task {
	return Task{
		Name:        "license-validations",
		Description: "verify dependency licenses via grant (self-check)",
		RunsOn:      lang.List("static-analysis"),
		Run: func() {
			var sbom bytes.Buffer
			Run("syft -o json --override-default-catalogers go-module-file-cataloger dir:.", run.Stdout(&sbom))
			Run("grant check -c .grant.yaml -", run.Stdin(&sbom))
		},
	}
}

// generateTasks runs the code generators for the SPDX license index and
// license search patterns. The patterns generator depends on the SPDX index.
func generateTasks() Task {
	return Task{
		Name:        "generate",
		Description: "generate SPDX license index and license patterns",
		Run: func() {
			Run("go run ./internal/spdxlicense/generate")
			Run("go run ./internal/licensepatterns/generate")
		},
		Tasks: []Task{
			{
				Name:        "generate:spdx-licenses",
				Description: "generate SPDX license index from latest SPDX license list",
				Run: func() {
					Run("go run ./internal/spdxlicense/generate")
				},
			},
			{
				Name:         "generate:license-patterns",
				Description:  "generate license file search patterns",
				Dependencies: lang.List("generate:spdx-licenses"),
				Run: func() {
					Run("go run ./internal/licensepatterns/generate")
				},
			},
		},
	}
}

// demoTask generates the project demo GIF using VHS.
func demoTask() Task {
	return Task{
		Name:        "demo",
		Description: "generate demo GIF using VHS",
		Run: func() {
			Run("vhs .github/images/demo.tape")
		},
	}
}

// findMalformedFilenames walks the tree under root and returns an error
// listing any path containing ':' — a known cross-platform foot-gun for Go
// modules. Mirrors the behavior of go-make's internal helper.
func findMalformedFilenames(root string) error {
	var bad []string
	err := filepath.Walk(root, func(path string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.Contains(path, ":") {
			bad = append(bad, path)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("error walking through files: %w", err)
	}
	if len(bad) > 0 {
		fmt.Println("\nfound unsupported filename characters:")
		for _, p := range bad {
			fmt.Println(p)
		}
		return fmt.Errorf("\nerror: unsupported filename characters found")
	}
	return nil
}
