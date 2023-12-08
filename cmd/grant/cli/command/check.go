package command

import (
	"fmt"
	"os"
	"slices"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grant/cmd/grant/cli/internal/check"
	"github.com/anchore/grant/cmd/grant/cli/option"
	"github.com/anchore/grant/grant"
	"github.com/anchore/grant/internal/input"
)

type CheckConfig struct {
	Config       string `json:"config" yaml:"config" mapstructure:"config"`
	Format       string `json:"format" yaml:"format" mapstructure:"format"`
	option.Check `json:"" yaml:",inline" mapstructure:",squash"`
}

func Check(app clio.Application) *cobra.Command {
	cfg := &CheckConfig{
		Check:  option.DefaultCheck(),
		Format: string(check.Table),
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

func runCheck(cfg CheckConfig, userInput []string) (errs error) {
	// check if user provided source by stdin
	// note: cat sbom.json | grant check spdx.json - is supported
	// it will generate results for both stdin and spdx.json
	isStdin, _ := input.IsStdinPipeOrRedirect()
	if isStdin && !slices.Contains(userInput, "-") {
		userInput = append(userInput, "-")
	}

	policy, err := grant.NewPolicy(cfg.AllowLicenses, cfg.DenyLicenses, cfg.IgnoreLicenses)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("could not check licenses; could not build policy from config: %s", cfg.Config))
	}

	// TODO: we need to support the ability to write the report to a file without redirecting stdout
	checkConfig := check.Config{
		Policy: policy,
	}

	rep, err := check.NewReport(check.Table, checkConfig, userInput...)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("unable to create report for inputs %s", userInput))
	}

	return rep.Render(os.Stdout)
}
