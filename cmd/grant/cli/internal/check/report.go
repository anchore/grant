package check

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gookit/color"
	list "github.com/jedib0t/go-pretty/v6/list"

	"github.com/anchore/grant/cmd/grant/cli/internal"
	"github.com/anchore/grant/event"
	"github.com/anchore/grant/grant"
	"github.com/anchore/grant/grant/evalutation"
	"github.com/anchore/grant/internal/bus"
)

// Report presents the results of a grant check command `grant alpine:latest ./foo`
// The above command will have two results.
// The first result is easy. Generate an SBOM for alpine:latest and run the policy against it.
// The second result is a little more complicated. Visit each leaf of ./foo and check for licenses, sbom, or archives.
// Results are composed of a case its evaluations. The case is the total of SBOM/Licenses generated from the user request.
// The evaluations are the individual assessments of the policy against the packages/licenses in the case.
type Report struct {
	ReportID  string
	Results   evalutation.Results
	Config    ReportConfig
	Timestamp string
	Monitor   *event.ManualStagedProgress
	errors    []error
}

type ReportConfig struct {
	Policy  grant.Policy
	Options internal.ReportOptions
	Monitor *event.ManualStagedProgress
}

// NewReport will generate a new report for the given format for the check command
// The supplied policy is applied to all user requests.
// If no policy is provided, the default policy will be used
// If no requests are provided, an empty report will be generated
// If a request is provided, but the sbom cannot be generated, the source will be ignored and an error will be returned
// Where do we render packages that had no licenses?
func NewReport(rc ReportConfig, userRequests ...string) (*Report, error) {
	if rc.Policy.IsEmpty() {
		rc.Policy = grant.DefaultPolicy()
	}

	rc.Options.Format = internal.ValidateFormat(rc.Options.Format)
	
	// Convert internal options to grant config
	grantConfig := grant.CaseConfig{
		SBOMOnly: rc.Options.SBOMOnly,
	}
	cases := grant.NewCasesWithConfig(grantConfig, userRequests...)
	ec := evalutation.EvaluationConfig{
		Policy:       rc.Policy,
		CheckNonSPDX: rc.Options.CheckNonSPDX,
		OsiApproved:  rc.Options.OsiApproved,
	}

	results := evalutation.NewResults(ec, cases...)

	return &Report{
		Results:   results,
		Config:    rc,
		Timestamp: time.Now().Format(time.RFC3339),
		Monitor:   rc.Monitor,
	}, nil
}

// Render will call Render on each result in the report and return the report
func (r *Report) Render() error {
	switch r.Config.Options.Format {
	case internal.Table:
		return r.renderCheckTree()
	case internal.JSON:
		return r.renderJSON()
	default:
		r.errors = append(r.errors, fmt.Errorf("invalid format: %s; valid formats are: %s", r.Config.Options.Format, internal.ValidFormats))
		return errors.Join(r.errors...)
	}
}

func (r *Report) HasFailures() bool {
	return r.Results.IsFailed()
}

type Response struct {
	ReportID  string       `json:"report_id" yaml:"report_id"`
	Timestamp string       `json:"timestamp" yaml:"timestamp"`
	Inputs    []string     `json:"inputs" yaml:"inputs"`
	Results   []Evaluation `json:"results" yaml:"results"`
}

type Evaluation struct {
	Input   string           `json:"input" yaml:"input"`
	License internal.License `json:"license" yaml:"license"`
	Package internal.Package `json:"package" yaml:"package"`
	Passed  bool             `json:"passed" yaml:"passed"`
	Reasons []string         `json:"reasons" yaml:"reasons"`
}

func NewEvaluation(input string, le evalutation.LicenseEvaluation) Evaluation {
	reasons := make([]string, 0)
	for _, r := range le.Reason {
		if r.RuleName == "" {
			reasons = append(reasons, r.Detail)
			continue
		}
		details := fmt.Sprintf("%s: %s", r.RuleName, r.Detail)
		reasons = append(reasons, details)
	}

	license := internal.NewLicense(le.License)
	var pkg internal.Package
	if le.Package != nil {
		pkg = internal.NewPackage(le.Package)
	}

	re := Evaluation{
		Input:   input,
		License: license,
		Package: pkg,
		Passed:  le.Pass,
		Reasons: reasons,
	}

	return re
}

func (r *Report) renderJSON() error {
	evaluations := make([]Evaluation, 0)
	for _, res := range r.Results {
		for _, e := range res.Evaluations {
			re := NewEvaluation(res.Case.UserInput, e)
			evaluations = append(evaluations, re)
		}
	}
	report := Response{
		ReportID:  r.ReportID,
		Timestamp: r.Timestamp,
		Inputs:    r.Results.UserInputs(),
		Results:   evaluations,
	}
	jsonData, err := json.Marshal(report)
	if err != nil {
		return err
	}

	bus.Report(string(jsonData))
	return nil
}

func (r *Report) renderCheckTree() error {
	var uiLists []list.Writer
	for _, res := range r.Results {
		r.Monitor.Increment()
		r.Monitor.AtomicStage.Set(res.Case.UserInput)
		resulList := newList()
		uiLists = append(uiLists, resulList)
		resulList.AppendItem(color.Primary.Sprintf("%s", res.Case.UserInput))

		for _, rule := range r.Config.Policy.Rules {
			failedEvaluations := r.Results.GetFailedEvaluations(res.Case.UserInput, rule)
			if len(failedEvaluations) == 0 {
				resulList.Indent()
				resulList.AppendItem(color.Success.Sprintf("No License Violations Found for Rule %s", rule.Name))
				resulList.UnIndent()
				continue
			}
			renderEvaluations(rule, r.Config.Options.ShowPackages, resulList, failedEvaluations)
		}
		if r.Config.Options.OsiApproved {
			osiRule := grant.Rule{
				Name: evalutation.RuleNameNotOSIApproved,
			}

			failedEvaluations := r.Results.GetFailedEvaluations(res.Case.UserInput, osiRule)
			if len(failedEvaluations) == 0 {
				resulList.Indent()
				resulList.AppendItem(color.Success.Sprintf("%s", "No OSI Violations Found"))
				resulList.UnIndent()
			} else {
				renderEvaluations(osiRule, r.Config.Options.ShowPackages, resulList, failedEvaluations)
			}
		}
		if r.Config.Options.ShowPackages {
			renderOrphanPackages(resulList, res, false) // keep primary coloring for tree
		}
	}
	r.Monitor.AtomicStage.Set(strings.Join(r.Results.UserInputs(), ", "))
	// segment the results into lists by user input
	// lists can optionally show the packages that were evaluated

	for _, l := range uiLists {
		bus.Report(l.Render())
	}
	return nil
}

func renderOrphanPackages(l list.Writer, res evalutation.Result, invert bool) {
	title := color.Secondary
	newItem := color.Light
	if invert {
		title = color.Light
		newItem = color.Secondary
	}
	// TODO: there is a bug here where binary cataloger show even when dupe os overlap
	orphans := res.Evaluations.EmptyPackages()
	if len(orphans) == 0 {
		return
	}
	l.Indent()
	l.AppendItem(title.Sprintf("packages found with no licenses"))
	l.Indent()
	for _, pkg := range orphans {
		l.AppendItem(newItem.Sprintf("%s", pkg))
	}
	l.UnIndent()
	l.UnIndent()
}

func renderEvaluations(rule grant.Rule, showPackages bool, l list.Writer, e evalutation.LicenseEvaluations) {
	l.Indent()
	l.AppendItem(color.Secondary.Sprintf("license matches for rule: %s; matched with pattern %s", rule.Name, rule.OriginalPattern))

	licenseTracker := make(map[string]struct{})
	for _, eval := range e {
		var license string
		if eval.License.SPDXExpression != "" {
			license = eval.License.SPDXExpression
		} else {
			license = eval.License.Name
		}
		if _, ok := licenseTracker[license]; !ok {
			licenseTracker[license] = struct{}{}
			l.Indent()
			l.AppendItem(color.Danger.Sprintf("%s", license))
			if showPackages {
				packages := e.Packages(license)
				l.Indent()
				for _, pkg := range packages {
					l.AppendItem(color.Light.Sprintf("%s", pkg))
				}
				l.UnIndent()
			}
			l.UnIndent()
		}
	}
	l.UnIndent()
}

func newList() list.Writer {
	l := list.NewWriter()
	return l
}
