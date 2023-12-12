package command

import (
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grant/cmd/grant/cli/internal/check"
	"github.com/anchore/grant/cmd/grant/cli/option"
	"github.com/anchore/grant/event"
	"github.com/anchore/grant/grant"
	"github.com/anchore/grant/internal/bus"
	"github.com/anchore/grant/internal/input"
)

type ListConfig struct {
	Config      string `json:"config" yaml:"config" mapstructure:"config"`
	option.List `json:"" yaml:",inline" mapstructure:",squash"`
}

func List(app clio.Application) *cobra.Command {
	cfg := &ListConfig{
		List: option.DefaultList(),
	}

	// userInputs are the oci images, sboms, or directories/files to check
	var userInputs []string
	return app.SetupCommand(&cobra.Command{
		Use:   "list",
		Short: "List the licenses detected in the given OCI image, sbom, or directory/file",
		Args:  cobra.ArbitraryArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			userInputs = args
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(cfg, userInputs)
		},
	}, cfg)
}

func runList(cfg *ListConfig, userInput []string) (errs error) {
	// check if user provided source by stdin
	// note: cat sbom.json | grant check spdx.json - is supported
	// it will generate results for both stdin and spdx.json
	isStdin, _ := input.IsStdinPipeOrRedirect()
	if isStdin && !slices.Contains(userInput, "-") {
		userInput = append(userInput, "-")
	}

	monitor := bus.PublishTask(
		event.Title{
			Default:      "List licenses",
			WhileRunning: "Looking up licenses",
			OnSuccess:    "Found licenses",
		},
		"",
		len(userInput),
	)

	defer func() {
		if errs != nil {
			monitor.SetError(errs)
		} else {
			monitor.AtomicStage.Set(strings.Join(userInput, ", "))
			monitor.SetCompleted()
		}
	}()

	reportConfig := check.ReportConfig{
		Format:       check.Format(cfg.Format),
		ShowPackages: cfg.ShowPackages,
		CheckNonSPDX: cfg.CheckNonSPDX,
		Policy:       grant.DefaultPolicy(),
		Monitor:      monitor,
	}
	rep, err := check.NewReport(reportConfig, userInput...)
	if err != nil {
		return err
	}
	return rep.RenderList()
}
