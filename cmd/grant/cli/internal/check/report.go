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
	ReportID     string
	Results      evalutation.Results
	Format       Format
	ShowPackages bool
	Timestamp    string
	errors       []error
}

// NewReport will generate a new report for the given format.
// The supplied policy is applied to all user requests.
// If no policy is provided, the default policy will be used
// If no requests are provided, an empty report will be generated
// If a request is provided, but the sbom cannot be generated, the source will be ignored and an error will be returned
// Where do we render packages that had no licenses?
func NewReport(f Format, rp grant.Policy, showPackages, checkNonSPDX bool, userRequests ...string) (*Report, error) {
	if rp.IsEmpty() {
		rp = grant.DefaultPolicy()
	}

	format := validateFormat(f)
	cases := grant.NewCases(rp, userRequests...)
	ec := evalutation.EvaluationConfig{
		Policy:       rp,
		CheckNonSPDX: checkNonSPDX,
	}

	results := evalutation.NewResults(ec, cases...)

	return &Report{
		Results:      results,
		Format:       format,
		ShowPackages: showPackages,
		Timestamp:    time.Now().Format(time.RFC3339),
	}, nil
}

// Render will call Render on each result in the report and return the report
func (r *Report) Render(out io.Writer) error {
	switch r.Format {
	case Table:
		return r.renderTable(out)
	case JSON:
		return errors.New("json format not yet supported")
	}
	return errors.Join(r.errors...)
}

func (r *Report) renderTable(out io.Writer) error {
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
			renderEvaluations(rule, r.ShowPackages, resulList, failedEvaluations)
		}

	}

	// segment the results into lists by user input
	// lists can optionally show the packages that were evaluated
	for _, l := range uiLists {
		bus.Report(l.Render())
	}
	return nil
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
			l.UnIndent()
		}
	}
	return
}

func newList() list.Writer {
	l := list.NewWriter()
	return l
}
