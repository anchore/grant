package check

import (
	"errors"
	"io"
	"time"

	"github.com/anchore/grant/grant"
	"github.com/anchore/grant/grant/evalutation"
)

// Report presents the results of a grant check command `grant alpine:latest ./foo`
// The above command will have two results.
// The first result is easy. Generate an SBOM for alpine:latest and run the policy against it.
// The second result is a little more complicated. Visit each leaf of ./foo and check for licenses, sbom, or archives.
// Results are composed of a case its evaluations. The case is the total of SBOM/Licenses generated from the user request.
// The evaluations are the individual assessments of the policy against the packages/licenses in the case.
type Report struct {
	ReportID  string
	Results   []evalutation.Result `json:"results" yaml:"results"`
	Format    Format               `json:"format" yaml:"format"`
	Timestamp string               `json:"timestamp" yaml:"timestamp"`
	errors    []error
}

type Config struct {
	Policy *grant.Policy
}

// NewReport will generate a new report for the given format.
// The supplied policy is applied to all user requests.
// If no policy is provided, the default policy will be used
// If no requests are provided, an empty report will be generated
// If a request is provided, but the sbom cannot be generated, the source will be ignored and an error will be returned
func NewReport(f Format, cc Config, userRequests ...string) (*Report, error) {
	if cc.Policy.IsEmpty() {
		cc.Policy = grant.DefaultPolicy()
	}

	format := validateFormat(f)
	cases := grant.NewCases(cc.Policy, userRequests...)
	ec := evalutation.EvaluationConfig{
		Policy:       cc.Policy,
		CheckNonSPDX: true,
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
	case JSON:
		return r.renderJSON(out)
	case Table:
		return r.renderTable(out)
	}
	return errors.Join(r.errors...)
}

func (r *Report) renderJSON(out io.Writer) error {
	return errors.New("not implemented")
}

func (r *Report) renderTable(out io.Writer) error {

}

//	l := list.NewWriter() // TODO: style me
//	customStyle := list.Style{
//		Format:           text.FormatTitle,
//		CharItemSingle:   "",
//		CharItemTop:      "",
//		CharItemFirst:    "",
//		CharItemMiddle:   "",
//		CharItemVertical: "  ",
//		CharItemBottom:   "",
//		CharNewline:      "\n",
//		LinePrefix:       "",
//		Name:             "customStyle",
//	}
//	l.SetStyle(customStyle)
//	for _, report := range reports {
//		if len(report.PackageViolations) == 0 {
//			l.AppendItem("No License Violations: ✅")
//			continue
//		}
//
//		l.AppendItem("License Violations:")
//		for license, pkg := range report.LicenseViolations {
//			l.AppendItem(fmt.Sprintf("%s %s", fmt.Sprint("-"), license))
//			// TODO: we probably want a flag that can turn this on
//			for _, p := range pkg {
//				l.Indent()
//				l.AppendItem(fmt.Sprintf("%s %s", fmt.Sprint("-"), p))
//				l.UnIndent()
//			}
//			l.UnIndent()
//		}
//	}
//
//	bus.Report(l.Render())
//	return nil
//}

//type ResultSummary struct {
//	CompliantPackages int `json:"compliant_packages" yaml:"compliant_packages"`
//	PackageViolations int `json:"package_violations" yaml:"package_violations"`
//	IgnoredPackages   int `json:"ignored_packages" yaml:"ignored_packages"`
//	LicenseViolations int `json:"license_violations" yaml:"license_violations"`
//	CompliantLicenses int `json:"compliant_licenses" yaml:"compliant_licenses"`
//	IgnoredLicenses   int `json:"ignored_licenses" yaml:"ignored_licenses"`
//}
//
//func (r *Result) Summary() ResultSummary {
//	return ResultSummary{
//		CompliantPackages: len(r.CompliantPackages),
//		PackageViolations: len(r.PackageViolations),
//		IgnoredPackages:   len(r.IgnoredPackages),
//		LicenseViolations: len(r.LicenseViolations),
//		CompliantLicenses: len(r.CompliantLicenses),
//		IgnoredLicenses:   len(r.IgnoredLicenses),
//	}
//}
