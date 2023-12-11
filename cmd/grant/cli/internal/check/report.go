package check

import (
	"errors"
	"io"
	"time"

	list "github.com/jedib0t/go-pretty/v6/list"
	"github.com/jedib0t/go-pretty/v6/text"

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
func NewReport(f Format, rp grant.Policy, userRequests ...string) (*Report, error) {
	if rp.IsEmpty() {
		rp = grant.DefaultPolicy()
	}

	format := validateFormat(f)
	cases := grant.NewCases(rp, userRequests...)
	ec := evalutation.EvaluationConfig{
		Policy:       rp,
		CheckNonSPDX: true, // TODO: how do we design the configuration here to inject this value?
	}

	results := evalutation.NewResults(ec, cases...)

	return &Report{
		Results:   results,
		Format:    format,
		Timestamp: time.Now().Format(time.RFC3339),
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
	if !r.Results.IsFailed() {
		l := newList()
		l.AppendItem("No License Violations Found: ✅")
		bus.Report(l.Render())
		return nil
	}

	var uiLists []list.Writer
	failedEvaluations := r.Results.GetFailedEvaluations()

	// segment the results into lists by user input
	// lists can optionally show the packages that were evaluated
	for input, eval := range failedEvaluations {
		l := newList()
		uiLists = append(uiLists, l)
		l.AppendItem(input)
		l.Indent()
		renderLicenses(l, eval)
		l.UnIndent()
	}
	for _, l := range uiLists {
		bus.Report(l.Render())
	}
	return nil
}

func renderLicenses(l list.Writer, evals evalutation.LicenseEvaluations) {
	duplicates := make(map[string]struct{})
	for _, e := range evals {
		var licenseRender string
		if e.License.IsSPDX() {
			licenseRender = e.License.SPDXExpression
		} else {
			licenseRender = e.License.Name
		}
		if _, ok := duplicates[licenseRender]; ok {
			continue
		}
		duplicates[licenseRender] = struct{}{}
		l.Indent()
		l.AppendItem(licenseRender)
		l.UnIndent()
	}
}

func newList() list.Writer {
	l := list.NewWriter()
	reportStyle := list.Style{
		Format:         text.FormatDefault,
		CharItemSingle: "▶",
		CharItemTop:    "-",
		CharItemFirst:  "-",
		CharItemMiddle: "-",
		CharItemBottom: "-",
		CharNewline:    "\n",
		LinePrefix:     "",
		Name:           "styleTest",
	}
	l.SetStyle(reportStyle)

	return l
}

type ResultSummary struct {
	CompliantPackages int `json:"compliant_packages" yaml:"compliant_packages"`
	PackageViolations int `json:"package_violations" yaml:"package_violations"`
	IgnoredPackages   int `json:"ignored_packages" yaml:"ignored_packages"`
	LicenseViolations int `json:"license_violations" yaml:"license_violations"`
	CompliantLicenses int `json:"compliant_licenses" yaml:"compliant_licenses"`
	IgnoredLicenses   int `json:"ignored_licenses" yaml:"ignored_licenses"`
}

func Summary() ResultSummary {
	return ResultSummary{}
}
