package command

import (
	"fmt"
	"slices"
	"strings"

	"github.com/gobwas/glob"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grant/cmd/grant/cli/internal"
	"github.com/anchore/grant/cmd/grant/cli/internal/check"
	"github.com/anchore/grant/cmd/grant/cli/option"
	"github.com/anchore/grant/event"
	"github.com/anchore/grant/grant"
	"github.com/anchore/grant/internal/bus"
	"github.com/anchore/grant/internal/input"
)

var ErrPolicyFailure = errors.New("check failed")

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
		PreRunE: func(_ *cobra.Command, args []string) error {
			userInputs = args
			return nil
		},
		RunE: func(_ *cobra.Command, _ []string) error {
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

	monitor := bus.PublishTask(
		event.Title{
			Default:      "Check licenses",
			WhileRunning: "Checking licenses",
			OnSuccess:    "Checked licenses",
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

	policy, err := grant.NewPolicy(cfg.NonSPDX, rules...)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("could not check licenses; could not build policy from config: %s", cfg.Config))
	}

	reportConfig := check.ReportConfig{
		Policy: policy,
		Options: internal.ReportOptions{
			Format:            internal.Format(cfg.Output),
			ShowPackages:      cfg.ShowPackages,
			CheckNonSPDX:      cfg.NonSPDX,
			OsiApproved:       cfg.OsiApproved,
			DisableFileSearch: cfg.DisableFileSearch,
		},
		Monitor: monitor,
	}
	rep, err := check.NewReport(reportConfig, userInput...)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("unable to create report for inputs %s", userInput))
	}

	err = rep.Render()
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("unable to render report for inputs %s", userInput))
	}
	if rep.HasFailures() {
		return ErrPolicyFailure
	}
	return nil
}
