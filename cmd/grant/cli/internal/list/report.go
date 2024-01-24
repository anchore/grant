package list

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/gookit/color"
	"github.com/jedib0t/go-pretty/v6/list"

	"github.com/anchore/grant/cmd/grant/cli/internal"
	"github.com/anchore/grant/event"
	"github.com/anchore/grant/grant"
	"github.com/anchore/grant/internal/bus"
)

type Report struct {
	ReportID  string
	Cases     []grant.Case
	Config    ReportConfig
	Timestamp string
	Monitor   *event.ManualStagedProgress
	errors    []error
}

type ReportConfig struct {
	Options internal.ReportOptions
	Monitor *event.ManualStagedProgress
}

// NewReport will generate a new report for the given format for the list command.
// The supplied policy is applied to all user requests.
// If no policy is provided, the default policy will be used
// If no requests are provided, an empty report will be generated
// If a request is provided, but the sbom cannot be generated, the source will be ignored and an error will be returned
// Where do we render packages that had no licenses?
func NewReport(rc ReportConfig, userRequests ...string) (*Report, error) {
	rc.Options.Format = internal.ValidateFormat(rc.Options.Format)
	cases := grant.NewCases(userRequests...)

	return &Report{
		ReportID:  internal.NewReportID(),
		Cases:     cases,
		Config:    rc,
		Timestamp: time.Now().Format(time.RFC3339),
		Monitor:   rc.Monitor,
	}, nil
}

func (r *Report) Render() error {
	switch r.Config.Options.Format {
	case internal.Table:
		return r.renderList()
	case internal.JSON:
		return r.renderJSON()
	default:
		r.errors = append(r.errors, fmt.Errorf("invalid format: %s; valid formats are: %s", r.Config.Options.Format, internal.ValidFormats))
		return errors.Join(r.errors...)
	}
}

type Response struct {
	ReportID  string   `json:"report_id" yaml:"report_id"`
	Timestamp string   `json:"timestamp" yaml:"timestamp"`
	Inputs    []string `json:"inputs" yaml:"inputs"`
	Results   []Result `json:"results" yaml:"results"`
}

type Result struct {
	Input   string           `json:"input" yaml:"input"`
	License internal.License `json:"license" yaml:"license"`
	Package internal.Package `json:"package" yaml:"package"`
}

func NewResult(input string, gl grant.License, gp *grant.Package) Result {
	rl := internal.NewLicense(gl)
	rp := internal.NewPackage(gp)
	return Result{
		Input:   input,
		License: rl,
		Package: rp,
	}
}

func (r *Report) renderJSON() error {
	resp := Response{
		ReportID:  r.ReportID,
		Timestamp: r.Timestamp,
		Inputs:    make([]string, 0),
		Results:   make([]Result, 0),
	}

	for _, c := range r.Cases {
		resp.Inputs = append(resp.Inputs, c.UserInput)
		// TODO: is it better to invert this here and grab packages -> licenses since package is the cases first class
		licenses, _ := c.GetLicenses()
		for _, pairs := range licenses {
			for _, pair := range pairs {
				resp.Results = append(resp.Results, NewResult(c.UserInput, pair.License, pair.Package))
			}
		}
	}
	jsonData, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	bus.Report(string(jsonData))
	return nil
}

func (r *Report) renderList() error {
	var uiLists []list.Writer
	for _, c := range r.Cases {
		r.Monitor.Increment()
		r.Monitor.AtomicStage.Set(c.UserInput)
		resultList := list.NewWriter()
		uiLists = append(uiLists, resultList)
		resultList.AppendItem(color.Primary.Sprintf("%s", c.UserInput))
		pairs, _ := c.GetLicenses()
		resultList.Indent()
		for key, _ := range pairs {
			resultList.AppendItem(color.Primary.Sprintf("%s", key))
		}
		resultList.UnIndent()
	}

	for _, l := range uiLists {
		bus.Report(l.Render())
	}
	return nil
}
