package grant

import (
	"fmt"
	"time"

	"github.com/pkg/errors"

	"github.com/anchore/grant/internal/input"
	"github.com/anchore/syft/syft/format"
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
	Timestamp string  `json:"timestamp" yaml:"timestamp"`
	errors    []error
}

// NewReport will generate a new report for the given sources and policy
// If no policy is provided, the default policy will be used
// If no sources are provided, an empty report will be generated
// If a source is provided, but the sbom cannot be generated, the source will be ignored
// If a source is provided, but the sbom cannot be decoded, the source will be ignored
// Results will be generated and evaluated for each source that is successfully processed
func NewReport(policy *Policy, srcs ...string) *Report {
	if policy == nil || policy.IsEmpty() {
		policy = DefaultPolicy()
	}

	results := make([]Result, 0)
	errs := make([]error, 0)
	for _, src := range srcs {
		reader, err := input.GetReader(src)
		if err != nil {
			errs = append(errs, errors.Wrap(err, fmt.Sprintf("could not check licenses; could not get reader for source: %s ", src)))
			continue
		}

		sbomDecoders := format.NewDecoderCollection(format.Decoders()...)
		sbom, formatID, version, err := sbomDecoders.Decode(reader)
		if err != nil {
			errs = append(errs, errors.Wrap(err, fmt.Sprintf("could not build result; could not decode sbom: %s ", src)))
			continue
		}
		results = append(results, NewResult(policy, src, sbom, formatID.String(), version))
	}

	return &Report{
		Results:   results,
		Sources:   srcs,
		Policy:    policy,
		Timestamp: time.Now().Format(time.RFC3339),
		errors:    errs,
	}
}

// Run will call Generate on each result in the report
func (r *Report) Run() {
	for _, result := range r.Results {
		// TODO: add error tracking to reports for failed results
		err := result.Generate()
		if err != nil {
			r.errors = append(r.errors, errors.Wrap(err, fmt.Sprintf("failed to generate result for source: %s", result.Source)))
		}
	}
}
