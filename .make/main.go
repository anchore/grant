package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	. "github.com/anchore/go-make"
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
			// TODO: re-enable race detection once google/licenseclassifier/v2 fixes its data race
			// in ClassifyLicenses (see backend/backend.go:96-100). Currently triggers a false-positive
			// race report under TestHandleDir_SBOMLicenseScan in CI. go-make defaults Race=true in CI;
			// override here.
			func(c *gotest.Config) { c.Race = false },
		),
		gotest.FixtureTasks().RunOn("unit"),

		staticAnalysisTask(),
		licenseValidationTask(),

		generateTasks(),
		demoTask(),
	)
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
