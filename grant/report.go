package grant

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/anchore/grant/internal/input"
	syftFormat "github.com/anchore/syft/syft/format"
)

// Report tracks the results of a license check.
// For each source a report will generate a Result. A report can have multiple results.
// The report will track the policy used to generate the report and apply it to all results.
//
// Multiple sources can be configured for a report. A source can be one of the following
// Single Sources Provider:
// - a path to a sbom file (uses the given SBOM (spdx, cyclonedx, etc))
// TODO: - a path to a directory (generates an SBOM for the given directory)
// TODO: - a path to some archive (generates an SBOM for the given archive)
// TODO: - a path to a container image (generates an SBOM for the given image)
//
// Multiple Source Provider:
// - multiple paths to sbom files
// TODO: - a path to a directory containing sbom files
// TODO: - a path to a container image with sbom files
// TODO: - a path to a directory containing container images
// TODO: - a path to a directory containing container images and sbom files
type Report struct {
	// Results of the report for each source
	Results []Result `json:"results" yaml:"results"`
	// Sources included in the report
	Sources []string `json:"sources" yaml:"sources"`
	// Policy used to generate the report. Applies to all results
	Policy    *Policy `json:"policy" yaml:"policy"`
	Format    Format  `json:"format" yaml:"format"`
	Timestamp string  `json:"timestamp" yaml:"timestamp"`
	errors    []error
}

type Format string

const (
	JSON  Format = "json"
	Table Format = "table"
)

// NewReport will generate a new report for the given format, policy and sources
// If no policy is provided, the default policy will be used
// If no sources are provided, an empty report will be generated
// If a source is provided, but the sbom cannot be generated, the source will be ignored
// If a source is provided, but the sbom cannot be decoded, the source will be ignored
// Results will be generated and evaluated for each source that is successfully processed
func NewReport(f Format, policy *Policy, srcs ...string) *Report {
	if policy == nil || policy.IsEmpty() {
		policy = DefaultPolicy()
	}

	format := validateFormat(f)
	results := make([]Result, 0)
	errs := make([]error, 0)
	for _, src := range srcs {
		reader, err := input.GetReader(src)
		if err != nil {
			errs = append(errs, fmt.Errorf("%w; could not check licenses; could not get reader for source: %s ", err, src))
			continue
		}

		sbomDecoders := syftFormat.NewDecoderCollection(syftFormat.Decoders()...)
		sbom, formatID, version, err := sbomDecoders.Decode(reader)
		if err != nil {
			errs = append(errs, fmt.Errorf("%w; could not build result; could not decode sbom: %s ", err, src))
			continue
		}
		results = append(results, NewResult(policy, src, sbom, formatID.String(), version))
	}

	return &Report{
		Results:   results,
		Sources:   srcs,
		Policy:    policy,
		Format:    format,
		Timestamp: time.Now().Format(time.RFC3339),
		errors:    errs,
	}
}

// Run will call Generate on each result in the report and return the report
func (r *Report) Run() *Report {
	for _, result := range r.Results {
		err := result.Generate()
		if err != nil {
			r.errors = append(r.errors, fmt.Errorf("%w; failed to generate result for source: %s", err, result.Source))
		}
	}
	return r
}

// Render will call Render on each result in the report and return the report
func (r *Report) Render(out io.Writer) error {
	return errors.Join(r.errors...)
}

//func presentReports(reports []*grant.Report) error {
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

// validFormat returns a valid format or the default format if the given format is invalid
func validateFormat(f Format) Format {
	switch f {
	case "json":
		return JSON
	case "table":
		return Table
	default:
		return Table
	}
}
