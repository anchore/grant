package command

import (
	"fmt"
	"slices"
	"strings"

	"github.com/jedib0t/go-pretty/v6/list"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grant/cmd/grant/cli/option"
	"github.com/anchore/grant/event"
	"github.com/anchore/grant/grant"
	"github.com/anchore/grant/internal/bus"
	"github.com/anchore/grant/internal/input"
	"github.com/anchore/grant/internal/log"
	"github.com/anchore/syft/syft/format"
)

type CheckConfig struct {
	Config       string `json:"config" yaml:"config" mapstructure:"config"`
	option.Check `json:"" yaml:",inline" mapstructure:",squash"`
}

func Check(app clio.Application) *cobra.Command {
	cfg := &CheckConfig{
		Check: option.DefaultCheck(),
	}

	// sources are the oci images, sboms, or directories/files to check
	var sources []string
	return app.SetupCommand(&cobra.Command{
		Use:   "check",
		Short: "Verify licenses in the SBOM conform to the configured policy",
		Args:  cobra.ArbitraryArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			sources = args
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCheck(*cfg, sources)
		},
	}, cfg)
}

func runCheck(cfg CheckConfig, sources []string) (errs error) {
	var reports []*grant.Report
	// check if user provided source by stdin
	// note: cat sbom.json | grant check spdx.json - is supported
	// it will generate reports for both stdin and spdx.json
	isStdin, _ := input.IsStdinPipeOrRedirect()
	if isStdin && !slices.Contains(sources, "-") {
		sources = append(sources, "-")
	}

	monitor := bus.PublishTask(
		event.Title{
			Default:      "Check licenses from sources for non-compliance",
			WhileRunning: "Checking licenses from sources for non-compliance",
			OnSuccess:    "Checked licenses from sources for non-compliance",
		},
		"",
		len(sources),
	)

	defer func() {
		if errs != nil {
			monitor.SetError(errs)
		} else {
			monitor.AtomicStage.Set(strings.Join(sources, ", "))
			monitor.SetCompleted()
		}
	}()

	for _, src := range sources {
		monitor.Increment()
		monitor.AtomicStage.Set(src)

		// TODO: branch into source detection here to generate the sbom
		reader, err := input.GetReader(src)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("could not check licenses; could not get reader for source: %s ", src))
		}

		sbomDecoders := format.NewDecoderCollection(format.Decoders()...)
		sbom, formatID, version, err := sbomDecoders.Decode(reader)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("could not check licenses; could not decode sbom: %s ", src))
		}

		log.Debugf("found sbom format: %s, version: %s; checking licenses...", formatID, version)
		report := grant.NewReport(sbom.Source.Name, cfg.Check)
		for p := range sbom.Artifacts.Packages.Enumerate() {
			log.Debugf("checking package: %s for non compliant licenses...", p.Name)
			report.Check(p.Name, p.Licenses)
		}
		reports = append(reports, report)
	}

	// TODO: we need to return a non-zero exit code if any of the reports have a failure
	// Reports should have a custom render function for the default command usage
	// A machine readable json output should be available as well
	return presentReports(reports)
}

func presentReports(reports []*grant.Report) error {
	if len(reports) == 0 {
		bus.Report("no license compliance reports to show")
		return nil
	}

	l := list.NewWriter()
	customStyle := list.Style{
		Format:           text.FormatTitle,
		CharItemSingle:   "",
		CharItemTop:      "▶",
		CharItemFirst:    "",
		CharItemMiddle:   "",
		CharItemVertical: "  ",
		CharItemBottom:   "",
		CharNewline:      "\n",
		LinePrefix:       "",
		Name:             "customStyle",
	}
	l.SetStyle(customStyle)
	for _, report := range reports {
		l.AppendItem(fmt.Sprintf("Source: %s", report.Source))
		l.Indent()
		for pkg, _ := range report.CheckedPackages {
			l.AppendItem(fmt.Sprintf("Package: %s", pkg))
			l.AppendItem("Licenses: ")
			violations := report.Violations[pkg]
			compliance := report.Compliant[pkg]
			ignored := report.Ignored[pkg]
			if len(compliance) > 0 {
				l.Indent()
				for _, lic := range compliance {
					// green emoji check mark append
					l.AppendItem(fmt.Sprintf("%s %s", text.FgGreen.Sprint("- ✅"), lic))
				}
				l.UnIndent()
			}
			if len(violations) > 0 {
				l.Indent()
				for _, lic := range violations {
					// red emoji x mark append
					l.AppendItem(fmt.Sprintf("%s %s", text.FgRed.Sprint("- ❌"), lic))
				}
				l.UnIndent()
			}
			if len(ignored) > 0 {
				// grey emoji question mark append
				l.Indent()
				for _, lic := range ignored {
					l.AppendItem(fmt.Sprintf("%s %s", text.FgHiBlack.Sprint("- ❓"), lic))
				}
				l.UnIndent()
			}
		}
	}

	bus.Report(l.Render())
	return nil
}