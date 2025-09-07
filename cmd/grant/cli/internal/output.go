package internal

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/anchore/grant/grant"
)

// CheckResult represents the result of checking a single source
type CheckResult struct {
	Source           string                `json:"source" yaml:"source"`
	EvaluationResult grant.EvaluationResult `json:"evaluation" yaml:"evaluation"`
	Compliant        bool                  `json:"compliant" yaml:"compliant"`
}

// OutputCheckResults outputs the check results in the specified format
func OutputCheckResults(results []CheckResult, format string, showPackages bool) error {
	outputFormat := ValidateFormat(Format(format))
	
	switch outputFormat {
	case JSON:
		return outputCheckResultsJSON(results)
	case Table:
		return outputCheckResultsTable(results, showPackages)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

func outputCheckResultsJSON(results []CheckResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}

func outputCheckResultsTable(results []CheckResult, showPackages bool) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	defer w.Flush()

	// Header
	fmt.Fprintln(w, "SOURCE\tCOMPLIANT\tALLOWED\tDENIED\tIGNORED\tDETAILS")
	fmt.Fprintln(w, "------\t---------\t-------\t------\t-------\t-------")

	for _, result := range results {
		compliantStr := "✓"
		if !result.Compliant {
			compliantStr = "✗"
		}

		details := fmt.Sprintf("%d total packages", result.EvaluationResult.Summary.TotalPackages)
		
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%s\n",
			result.Source,
			compliantStr,
			result.EvaluationResult.Summary.AllowedPackages,
			result.EvaluationResult.Summary.DeniedPackages,
			result.EvaluationResult.Summary.IgnoredPackages,
			details,
		)

		if showPackages {
			printPackageDetails(w, &result.EvaluationResult)
		}
	}

	return nil
}

func printPackageDetails(w *tabwriter.Writer, result *grant.EvaluationResult) {
	// Print denied packages (most important)
	if len(result.DeniedPackages) > 0 {
		fmt.Fprintln(w, "\t\tDENIED PACKAGES:")
		for _, pkg := range result.DeniedPackages {
			licenses := extractLicenseNames(pkg.Package.Licenses)
			fmt.Fprintf(w, "\t\t  • %s (%s) - %s\n", pkg.Package.Name, strings.Join(licenses, ", "), pkg.Reason)
		}
	}

	// Print ignored packages
	if len(result.IgnoredPackages) > 0 {
		fmt.Fprintln(w, "\t\tIGNORED PACKAGES:")
		for _, pkg := range result.IgnoredPackages {
			fmt.Fprintf(w, "\t\t  • %s - %s\n", pkg.Package.Name, pkg.Reason)
		}
	}

	// Print allowed packages if not too many
	if len(result.AllowedPackages) > 0 && len(result.AllowedPackages) <= 10 {
		fmt.Fprintln(w, "\t\tALLOWED PACKAGES:")
		for _, pkg := range result.AllowedPackages {
			licenses := extractLicenseNames(pkg.Package.Licenses)
			fmt.Fprintf(w, "\t\t  • %s (%s)\n", pkg.Package.Name, strings.Join(licenses, ", "))
		}
	}
}

func extractLicenseNames(licenses []grant.License) []string {
	var names []string
	for _, license := range licenses {
		if license.SPDXExpression != "" {
			names = append(names, license.SPDXExpression)
		} else {
			names = append(names, license.Name)
		}
	}
	return names
}