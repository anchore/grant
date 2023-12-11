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
	Config    string        `json:"config" yaml:"config" mapstructure:"config"`
	DenyRules []option.Rule `json:"deny-rules" yaml:"deny-rules" mapstructure:"deny-rules"`
}

func DefaultCheck() *CheckConfig {
	return &CheckConfig{
		Config: "",
		DenyRules: []option.Rule{
			{
				Name:     "deny-all",
				Reason:   "grant by default will deny all licenses",
				Pattern:  "*",
				Severity: "high",
			},
		},
	}
}

func (cfg *CheckConfig) RulesFromConfig() (rules grant.Rules, err error) {
	rules = make(grant.Rules, 0)
	for _, rule := range cfg.DenyRules {
		pattern := strings.ToLower(rule.Pattern)
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
			Glob:       patternGlob,
			Exceptions: exceptions,
			Mode:       grant.Deny,
			Reason:     rule.Reason,
		})
	}
	return rules, nil
}

func Check(app clio.Application) *cobra.Command {
	cfg := DefaultCheck()
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
			return runCheck(cfg, sources)
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
	policy, err := grant.NewPolicy(rules...)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("could not check licenses; could not build policy from config: %s", cfg.Config))
	}

	rep, err := check.NewReport(check.Table, policy, userInput...)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("unable to create report for inputs %s", userInput))
	}

	return rep.Render(os.Stdout)
}
