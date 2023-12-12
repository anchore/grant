package command

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/gobwas/glob"
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
	option.Check `json:"" yaml:",inline" mapstructure:",squash"`
}

func (cfg *CheckConfig) RulesFromConfig() (rules grant.Rules, err error) {
	rules = make(grant.Rules, 0)
	for _, rule := range cfg.Rules {
		pattern := strings.ToLower(rule.Pattern) // all patterns are case insensitive
		patternGlob, err := glob.Compile(pattern)
		if err != nil {
			return rules, err
		}
		exceptions := make([]glob.Glob, 0)
		for _, exception := range rule.Exceptions {
			exception = strings.ToLower(exception)
			exceptionGlob, err := glob.Compile(exception)
			if err != nil {
				return rules, err
			}
			exceptions = append(exceptions, exceptionGlob)
		}
		rules = append(rules, grant.Rule{
			Name:               rule.Name,
			Glob:               patternGlob,
			OriginalPattern:    rule.Pattern,
			Exceptions:         exceptions,
			OriginalExceptions: rule.Exceptions,
			Mode:               grant.RuleMode(rule.Mode),
			Severity:           grant.RuleSeverity(rule.Severity),
			Reason:             rule.Reason,
		})
	}
	return rules, nil
}

func Check(app clio.Application) *cobra.Command {
	cfg := &CheckConfig{
		Check: option.DefaultCheck(),
	}

	// userInputs are the oci images, sboms, or directories/files to check
	var userInputs []string
	return app.SetupCommand(&cobra.Command{
		Use:   "check",
		Short: "Verify licenses in the SBOM conform to the configured policy",
		Args:  cobra.ArbitraryArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			userInputs = args
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCheck(cfg, userInputs)
		},
	}, cfg)
}

func runCheck(cfg *CheckConfig, userInput []string) (errs error) {
	// check if user provided source by stdin
	// note: cat sbom.json | grant check spdx.json - is supported
	// it will generate results for both stdin and spdx.json
	isStdin, _ := input.IsStdinPipeOrRedirect()
	if isStdin && !slices.Contains(userInput, "-") {
		userInput = append(userInput, "-")
	}

	rules, err := cfg.RulesFromConfig()
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("could not check licenses; could not build rules from config: %s", cfg.Config))
	}

	policy, err := grant.NewPolicy(cfg.CheckNonSPDX, rules...)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("could not check licenses; could not build policy from config: %s", cfg.Config))
	}

	rep, err := check.NewReport(check.Format(cfg.Format), policy, cfg.ShowPackages, cfg.CheckNonSPDX, userInput...)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("unable to create report for inputs %s", userInput))
	}

	return rep.Render(os.Stdout)
}
