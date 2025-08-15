package list

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
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

	grantConfig := grant.CaseConfig{
		DisableFileSearch: rc.Options.DisableFileSearch,
	}
	cases := grant.NewCasesWithConfig(grantConfig, userRequests...)

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
	case internal.CSV:
		return r.renderCSV()
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
	Input    string             `json:"input" yaml:"input"`
	License  internal.License   `json:"license" yaml:"license"`
	Packages []internal.Package `json:"packages" yaml:"packages"`
}

func NewResult(input string, gl grant.License, gp ...*grant.Package) Result {
	rl := internal.NewLicense(gl)
	pkgs := internal.NewPackages(gp...)
	return Result{
		Input:    input,
		License:  rl,
		Packages: pkgs,
	}
}

func (r *Report) renderCSV() error {
	response := getResponse(r)
	headers := []string{"component", "component_version", "license", "website", "type"}
	data := [][]string{
		headers,
	}

	for _, rslt := range response.Results {
		for _, pkg := range rslt.Packages {
			data = append(data, []string{
				pkg.Name,
				pkg.Version,
				rslt.License.Name,
				rslt.License.Reference,
				pkg.Type,
			})
		}
	}

	writer := csv.NewWriter(os.Stdout)
	defer writer.Flush()

	for _, record := range data {
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return writer.Error()
}

func getResponse(r *Report) Response {
	resp := Response{
		ReportID:  r.ReportID,
		Timestamp: r.Timestamp,
		Inputs:    make([]string, 0),
		Results:   make([]Result, 0),
	}

	for _, c := range r.Cases {
		resp.Inputs = append(resp.Inputs, c.UserInput)
		licensePackages, licenses, _ := c.GetLicenses()
		for key, l := range licenses {
			packages := licensePackages[key]
			result := NewResult(c.UserInput, l, packages...)
			resp.Results = append(resp.Results, result)
		}
	}
	return resp
}

func (r *Report) renderJSON() error {
	resp := getResponse(r)
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
		unsortedLicenses := make([]string, 0)
		resultList := list.NewWriter()
		uiLists = append(uiLists, resultList)
		resultList.AppendItem(color.Primary.Sprintf("%s", c.UserInput))
		packages, licenses, _ := c.GetLicenses()
		for _, license := range licenses {
			// Filter out SPDX licenses if requested to just show non-SPDX licenses
			if r.Config.Options.CheckNonSPDX && license.IsSPDX() {
				continue
			}
			if license.IsSPDX() {
				unsortedLicenses = append(unsortedLicenses, license.SPDXExpression)
				continue
			}
			unsortedLicenses = append(unsortedLicenses, license.Name)
		}

		// sort for list output
		slices.Sort(unsortedLicenses)

		resultList.Indent()
		for _, license := range unsortedLicenses {
			resultList.AppendItem(license)
			if r.Config.Options.ShowPackages {
				pkgs := packages[license]
				for _, pkg := range pkgs {
					resultList.Indent()
					resultList.AppendItem(pkg.Name)
					resultList.UnIndent()
				}
			}
		}
		resultList.UnIndent()
	}

	for _, l := range uiLists {
		bus.Report(l.Render())
	}
	return nil
}
