package command

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grant/cmd/grant/cli/internal"
	"github.com/anchore/grant/cmd/grant/cli/option"
	"github.com/anchore/grant/grant"
)

var ErrPolicyFailure = errors.New("check failed")

type CheckConfig struct {
	Config       string `json:"config" yaml:"config" mapstructure:"config"`
	option.Check `json:"" yaml:",inline" mapstructure:",squash"`
}

func Check(app clio.Application) *cobra.Command {
	cfg := &CheckConfig{
		Check: option.DefaultCheck(),
	}

	return app.SetupCommand(&cobra.Command{
		Use:   "check [SOURCE]...",
		Short: "check the licenses of packages in the given source",
		Long: "Check scans the given source (container image, directory, or SBOM file) for package license information " +
			"and evaluates it against the configured policy. By default, Grant denies all licenses except those " +
			"explicitly permitted in the 'allow' list.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCheck(cfg, args)
		},
	}, cfg)
}

func runCheck(cfg *CheckConfig, args []string) error {
	// Build policy from configuration
	policy, err := buildPolicy(cfg)
	if err != nil {
		return fmt.Errorf("failed to build policy: %w", err)
	}

	// Track overall results
	hasFailures := false
	var allResults []internal.CheckResult

	// Process each source
	for _, source := range args {

		// Generate case from source
		cases := grant.NewCasesWithConfig(grant.CaseConfig{
			DisableFileSearch: cfg.DisableFileSearch,
		}, source)

		if len(cases) == 0 {
			return fmt.Errorf("no cases generated for source: %s", source)
		}

		// Evaluate each case (typically just one per source)
		for _, c := range cases {
			result, err := c.Evaluate(policy)
			if err != nil {
				return fmt.Errorf("failed to evaluate case for source %q: %w", source, err)
			}

			// Convert to CLI result format
			checkResult := internal.CheckResult{
				Source:           source,
				EvaluationResult: *result,
				Compliant:        result.IsCompliant(),
			}
			allResults = append(allResults, checkResult)

			if !result.IsCompliant() {
				hasFailures = true
			}
		}
	}

	// Output results
	if err := internal.OutputCheckResults(allResults, cfg.Output, cfg.ShowPackages); err != nil {
		return fmt.Errorf("failed to output results: %w", err)
	}

	// Return error if any checks failed
	if hasFailures {
		return ErrPolicyFailure
	}

	return nil
}


func buildPolicy(cfg *CheckConfig) (*grant.Policy, error) {
	// If config file is specified, load from file
	if cfg.Config != "" {
		return grant.LoadPolicyFromFile(cfg.Config)
	}

	// Otherwise, build policy from CLI options
	policy := &grant.Policy{
		Allow:          cfg.Allow,
		IgnorePackages: cfg.IgnorePackages,
	}

	return policy, nil
}
