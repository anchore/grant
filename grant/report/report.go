package report

import (
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/anchore/grant/grant"
)

// Report tracks the requests/results of a license check.
// `grant alpine:latest ./foo` is a single report with two requests
// The first request is easy. Generate an SBOM for alpine:latest and run the policy against it.
// The second request is a little more complicated. Generate an SBOM for ./foo and run the policy against it.
// This is complex because the directory could contain multiple SBOMs, so we need to run the policy against each one.
// Requests have the string that generated the request along with a list of results for that request.
//
// Here is the summary of what multiple source inputs can be configured for a report.
// A source can be one of the following...
// Single Sources Provider:
// - a path to an sbom file (uses the given SBOM (spdx, cyclonedx, etc))
// - a path to a directory (generates an SBOM for the given directory) (no other sbom files in the directory)
// TODO: - a path to some archive (generates an SBOM for the given archive)
// TODO: - a path to a container image (generates an SBOM for the given image)
//
// Multiple Source Provider:
// - multiple paths to sbom files
// TODO: - a path to a directory containing sbom files
// TODO: - a path to a container image with sbom files
// TODO: - a path to a directory containing container images (1.tar.gz 2.tar.gz 3.tar.gz)
// TODO: - a path to a directory containing container images and sbom files
type Report struct {
	ReportID string
	Requests []Request `json:"results" yaml:"results"`

	// Evaluation is a pass/fail for the entire report;
	// It rolls up violations from all the requests
	Evaluation Evaluation `json:"evaluation" yaml:"evaluation"`
	Format     Format     `json:"format" yaml:"format"`
	Timestamp  string     `json:"timestamp" yaml:"timestamp"`
	errors     []error
}

// NewReport will generate a new report for the given format.
// The supplied policy is applied to all user requests.
// If no policy is provided, the default policy will be used
// If no requests are provided, an empty report will be generated
// If a request is provided, but the sbom cannot be generated, the source will be ignored
// Results will be generated and evaluated for each user request that is successfully processed
func NewReport(f Format, p grant.Policy, userRequests ...string) *Report {
	if p.IsEmpty() {
		p = grant.DefaultPolicy()
	}
	format := validateFormat(f)

	requests := make([]Request, 0)
	errs := make([]error, 0)
	for _, r := range userRequests {
		request, err := NewRequest(r, p)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		requests = append(requests, request)
	}

	return &Report{
		Requests:  requests,
		Format:    format,
		Timestamp: time.Now().Format(time.RFC3339),
		errors:    errs,
	}
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
	return json.NewEncoder(out).Encode(r)
}

func (r *Report) renderTable(out io.Writer) error {
	return nil
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
