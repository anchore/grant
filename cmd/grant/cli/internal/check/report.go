package check

import (
	"errors"
	"io"
	"time"

	"github.com/gookit/color"
	list "github.com/jedib0t/go-pretty/v6/list"

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
	errors    []error
}

type ReportConfig struct {
	Format       Format
	Policy       grant.Policy
	ShowPackages bool
	CheckNonSPDX bool
	OsiApproved  bool
}

// NewReport will generate a new report for the given format.
// The supplied policy is applied to all user requests.
// If no policy is provided, the default policy will be used
// If no requests are provided, an empty report will be generated
// If a request is provided, but the sbom cannot be generated, the source will be ignored and an error will be returned
// Where do we render packages that had no licenses?
func NewReport(rc ReportConfig, userRequests ...string) (*Report, error) {
	if rc.Policy.IsEmpty() {
		rc.Policy = grant.DefaultPolicy()
	}

	rc.Format = validateFormat(rc.Format)
	cases := grant.NewCases(rc.Policy, userRequests...)
	ec := evalutation.EvaluationConfig{
		Policy:       rc.Policy,
		CheckNonSPDX: rc.CheckNonSPDX,
		OsiApproved:  rc.OsiApproved,
	}

	results := evalutation.NewResults(ec, cases...)

	return &Report{
		Results:   results,
		Config:    rc,
		Timestamp: time.Now().Format(time.RFC3339),
	}, nil
}

// Render will call Render on each result in the report and return the report
func (r *Report) Render(out io.Writer) error {
	switch r.Config.Format {
	case Table:
		return r.renderCheckTree(out)
	case JSON:
		return errors.New("json format not yet supported")
	}
	return errors.Join(r.errors...)
}

func (r *Report) RenderList(out io.Writer) error {
	switch r.Config.Format {
	case Table:
		return r.renderList(out)
	case JSON:
		return errors.New("json format not yet supported")
	}
	return errors.Join(r.errors...)
}

func (r *Report) renderCheckTree(out io.Writer) error {
	var uiLists []list.Writer
	for _, res := range r.Results {
		resulList := newList()
		uiLists = append(uiLists, resulList)
		resulList.AppendItem(color.Primary.Sprintf("%s", res.Case.UserInput))

		for _, rule := range res.Case.Policy.Rules {
			failedEvaluations := r.Results.GetFailedEvaluations(res.Case.UserInput, rule)
			if len(failedEvaluations) == 0 {
				resulList.Indent()
				resulList.AppendItem(color.Success.Sprintf("%s", "No License Violations Found"))
				resulList.UnIndent()
				continue
			}
			renderEvaluations(rule, r.Config.ShowPackages, resulList, failedEvaluations)
		}
		if r.Config.OsiApproved {
			osiRule := grant.Rule{
				Name: evalutation.RuleNameNotOSIApproved,
			}
			failedEvaluations := r.Results.GetFailedEvaluations(res.Case.UserInput, osiRule)
			if len(failedEvaluations) == 0 {
				resulList.Indent()
				resulList.AppendItem(color.Success.Sprintf("%s", "No OSI Violations Found"))
				resulList.UnIndent()
			} else {
				renderEvaluations(osiRule, r.Config.ShowPackages, resulList, failedEvaluations)
			}
		}
		if r.Config.ShowPackages {
			renderOrphanPackages(resulList, res, false) // keep primary coloring for tree
		}
	}

	// segment the results into lists by user input
	// lists can optionally show the packages that were evaluated
	for _, l := range uiLists {
		bus.Report(l.Render())
	}
	return nil
}

func (r *Report) renderList(out io.Writer) error {
	var uiLists []list.Writer
	for _, res := range r.Results {
		resulList := newList()
		uiLists = append(uiLists, resulList)
		resulList.AppendItem(color.Primary.Sprintf("%s", res.Case.UserInput))
		for _, license := range res.Evaluations.GetLicenses() {
			resulList.Indent()
			resulList.AppendItem(color.Light.Sprintf("%s", license))
			resulList.UnIndent()
			if r.Config.ShowPackages {
				packages := res.Evaluations.Packages(license)
				resulList.Indent()
				resulList.Indent()
				for _, pkg := range packages {
					resulList.AppendItem(color.Secondary.Sprintf("%s", pkg))
				}
				resulList.UnIndent()
				resulList.UnIndent()
			}

		}
		renderOrphanPackages(resulList, res, true)
	}

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
	return
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
	return
}

func newList() list.Writer {
	l := list.NewWriter()
	return l
}
