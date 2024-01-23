package list

import (
	"time"

	"github.com/anchore/grant/cmd/grant/cli/internal"
	"github.com/anchore/grant/event"
	"github.com/anchore/grant/grant"
	"github.com/anchore/grant/grant/evalutation"
)

type Report struct {
	ReportID  string
	Results   evalutation.Results
	Config    ReportConfig
	Timestamp string
	Monitor   *event.ManualStagedProgress
	errors    []error
}

type ReportConfig struct {
	Options internal.ReportOptions
	Monitor *event.ManualStagedProgress
}

// NewReport will generate a new report for the given format.
// The supplied policy is applied to all user requests.
// If no policy is provided, the default policy will be used
// If no requests are provided, an empty report will be generated
// If a request is provided, but the sbom cannot be generated, the source will be ignored and an error will be returned
// Where do we render packages that had no licenses?
func NewReport(rc ReportConfig, userRequests ...string) (*Report, error) {
	rc.Options.Format = internal.ValidateFormat(rc.Options.Format)
	// TODO: we need a builder here that generates cases before the policy is applied
	cases := grant.NewCases(userRequests...)
	ec := evalutation.EvaluationConfig{
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
