package command

import (
	"fmt"
	"slices"

	"github.com/jedib0t/go-pretty/v6/list"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grant/cmd/grant/cli/option"
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

// TODO: upgrade the ui a bit with monitors for SBOM generation and license checking
// Progress can be incremented used on a per package basis when grant.Check is called
func runCheck(cfg CheckConfig, sources []string) (errs error) {
	var reports []*grant.Report
	// check if user provided source by stdin
	// note: cat sbom.json | grant check spdx.json - is supported
	// it will generate reports for both stdin and spdx.json
	isStdin, _ := input.IsStdinPipeOrRedirect()
	if isStdin && !slices.Contains(sources, "-") {
		sources = append(sources, "-")
	}

	for _, src := range sources {
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
		report := grant.NewReport(fmt.Sprintf("%s %s", sbom.Source.Name, sbom.Source.Version), cfg.Check)
		for p := range sbom.Artifacts.Packages.Enumerate() {
			log.Debugf("checking package: %s for non compliant licenses...", p.Name)
			licenses := grant.ConvertSyftLicenses(p.Licenses)
			report.Check(p.Name, licenses)
		}
		reports = append(reports, report)
	}

	// TODO: we need to return a non-zero exit code if any of the reports have a failure
	// Reports should have a custom render function for the default command usage
	// A machine readable json output should be available as well
	return presentReports(reports)
}

func presentReports(reports []*grant.Report) error {
	l := list.NewWriter() // TODO: style me
	customStyle := list.Style{
		Format:           text.FormatTitle,
		CharItemSingle:   "",
		CharItemTop:      "",
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
		if len(report.PackageViolations) == 0 {
			l.AppendItem("No License Violations: ✅")
			continue
		}

		l.AppendItem("License Violations:")
		for license, pkg := range report.LicenseViolations {
			l.AppendItem(fmt.Sprintf("%s %s", fmt.Sprint("-"), license))
			// TODO: we probably want a flag that can turn this on
			for _, p := range pkg {
				l.Indent()
				l.AppendItem(fmt.Sprintf("%s %s", fmt.Sprint("-"), p))
				l.UnIndent()
			}
			l.UnIndent()
		}
	}

	bus.Report(l.Render())
	return nil
}
