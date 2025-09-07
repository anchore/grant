package internal

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/gookit/color"
	
	"github.com/anchore/grant/grant"
)

// Output handles different output formats for grant results
type Output struct{}

// NewOutput creates a new Output instance
func NewOutput() *Output {
	return &Output{}
}

// OutputJSON outputs the result as JSON
func (o *Output) OutputJSON(result *grant.RunResponse) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// OutputTable outputs the result as a formatted table
func (o *Output) OutputTable(result *grant.RunResponse) error {
	for _, target := range result.Run.Targets {
		if err := o.outputTargetTable(target); err != nil {
			return err
		}
		fmt.Println() // Add spacing between targets
	}
	return nil
}

// outputTargetTable outputs a single target as a table
func (o *Output) outputTargetTable(target grant.TargetResult) error {
	// Print target header
	fmt.Printf("Target: %s (%s)\n", target.Source.Ref, target.Source.Type)
	fmt.Printf("Status: %s\n", o.formatStatus(target.Evaluation.Status))
	fmt.Println()
	
	// Print summary
	o.printSummary(target.Evaluation.Summary)
	fmt.Println()
	
	// Print detailed findings if there are packages
	if len(target.Evaluation.Findings.Packages) > 0 {
		return o.printPackageTable(target.Evaluation.Findings.Packages)
	}
	
	return nil
}

// formatStatus formats the status with colors
func (o *Output) formatStatus(status string) string {
	switch status {
	case "compliant":
		return color.Green.Sprint("✓ COMPLIANT")
	case "noncompliant":
		return color.Red.Sprint("✗ NON-COMPLIANT")
	case "error":
		return color.Red.Sprint("✗ ERROR")
	case "list":
		return color.Blue.Sprint("📋 LISTING")
	default:
		return strings.ToUpper(status)
	}
}

// printSummary prints the evaluation summary
func (o *Output) printSummary(summary grant.EvaluationSummaryJSON) {
	fmt.Println("Summary:")
	fmt.Printf("  Packages: %d total", summary.Packages.Total)
	
	if summary.Packages.Allowed > 0 {
		fmt.Printf(", %s allowed", color.Green.Sprint(summary.Packages.Allowed))
	}
	if summary.Packages.Denied > 0 {
		fmt.Printf(", %s denied", color.Red.Sprint(summary.Packages.Denied))
	}
	if summary.Packages.Ignored > 0 {
		fmt.Printf(", %s ignored", color.Yellow.Sprint(summary.Packages.Ignored))
	}
	if summary.Packages.Unlicensed > 0 {
		fmt.Printf(", %s unlicensed", color.Gray.Sprint(summary.Packages.Unlicensed))
	}
	fmt.Println()
	
	if summary.Licenses.Unique > 0 {
		fmt.Printf("  Licenses: %d unique", summary.Licenses.Unique)
		if summary.Licenses.Allowed > 0 {
			fmt.Printf(", %s allowed", color.Green.Sprint(summary.Licenses.Allowed))
		}
		if summary.Licenses.Denied > 0 {
			fmt.Printf(", %s denied", color.Red.Sprint(summary.Licenses.Denied))
		}
		if summary.Licenses.NonSPDX > 0 {
			fmt.Printf(", %s non-SPDX", color.Yellow.Sprint(summary.Licenses.NonSPDX))
		}
		fmt.Println()
	}
}

// printPackageTable prints packages in a table format
func (o *Output) printPackageTable(packages []grant.PackageFinding) error {
	if len(packages) == 0 {
		return nil
	}
	
	// Filter to only show denied packages
	deniedPackages := []grant.PackageFinding{}
	for _, pkg := range packages {
		if pkg.Decision == "deny" {
			deniedPackages = append(deniedPackages, pkg)
		}
	}
	
	if len(deniedPackages) == 0 {
		fmt.Println("No denied packages found.")
		return nil
	}
	
	// Sort denied packages alphabetically by name
	sort.Slice(deniedPackages, func(i, j int) bool {
		return deniedPackages[i].Name < deniedPackages[j].Name
	})
	
	// Create table
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleDefault)
	
	// Set headers - simplified to focus on the issues
	t.AppendHeader(table.Row{"Package", "Version", "Problematic Licenses"})
	
	// Add rows for denied packages only
	for _, pkg := range deniedPackages {
		// Only show the licenses that caused the denial
		problematicLicenses := o.formatProblematicLicenses(pkg.Licenses)
		version := pkg.Version
		if version == "" {
			version = "(no version)"
		}
		
		t.AppendRow(table.Row{
			pkg.Name,
			version,
			problematicLicenses,
		})
	}
	
	fmt.Printf("Denied Packages (%d):\n", len(deniedPackages))
	t.Render()
	return nil
}

// formatDecision formats the decision with colors
func (o *Output) formatDecision(decision string) string {
	switch decision {
	case "allow":
		return color.Green.Sprint("ALLOW")
	case "deny":
		return color.Red.Sprint("DENY")
	case "ignore":
		return color.Yellow.Sprint("IGNORE")
	case "list":
		return color.Blue.Sprint("LIST")
	default:
		return strings.ToUpper(decision)
	}
}

// formatLicenses formats the licenses for display
func (o *Output) formatLicenses(licenses []grant.LicenseDetail) string {
	if len(licenses) == 0 {
		return color.Gray.Sprint("(none)")
	}
	
	var formatted []string
	for _, license := range licenses {
		licenseStr := license.ID
		if license.Name != "" && license.ID == "" {
			licenseStr = license.Name
		}
		formatted = append(formatted, licenseStr)
	}
	
	return strings.Join(formatted, ", ")
}

// formatProblematicLicenses formats only the problematic licenses for denied packages
func (o *Output) formatProblematicLicenses(licenses []grant.LicenseDetail) string {
	if len(licenses) == 0 {
		return color.Red.Sprint("(no licenses found)")
	}
	
	var problematic []string
	for _, license := range licenses {
		licenseStr := license.ID
		if license.Name != "" && license.ID == "" {
			licenseStr = license.Name
		}
		
		// Shorten long license strings (like sha256 hashes)
		if strings.HasPrefix(licenseStr, "sha256:") && len(licenseStr) > 20 {
			licenseStr = "sha256:" + licenseStr[7:15] + "..."
		}
		
		// Format problematic licenses in red
		if licenseStr == "" || licenseStr == "(none)" {
			problematic = append(problematic, color.Red.Sprint("(unknown)"))
		} else {
			problematic = append(problematic, color.Red.Sprint(licenseStr))
		}
	}
	
	if len(problematic) == 0 {
		return color.Red.Sprint("(no licenses found)")
	}
	
	// If there are many licenses, show count
	if len(problematic) > 5 {
		return strings.Join(problematic[:5], ", ") + color.Gray.Sprintf(" (+%d more)", len(problematic)-5)
	}
	
	return strings.Join(problematic, ", ")
}

// formatLocations formats the locations for display
func (o *Output) formatLocations(locations []string) string {
	if len(locations) == 0 {
		return ""
	}
	
	// Show first location, indicate if there are more
	first := locations[0]
	if len(locations) > 1 {
		return fmt.Sprintf("%s (+%d more)", first, len(locations)-1)
	}
	return first
}

// OutputSummaryOnly outputs just the summary information
func (o *Output) OutputSummaryOnly(result *grant.RunResponse) error {
	totalCompliant := 0
	totalTargets := len(result.Run.Targets)
	
	for _, target := range result.Run.Targets {
		if target.Evaluation.Status == "compliant" {
			totalCompliant++
		}
	}
	
	if totalCompliant == totalTargets {
		fmt.Printf("%s All %d targets are compliant\n", color.Green.Sprint("✓"), totalTargets)
		return nil
	} else {
		nonCompliant := totalTargets - totalCompliant
		fmt.Printf("%s %d of %d targets are non-compliant\n", 
			color.Red.Sprint("✗"), nonCompliant, totalTargets)
		
		// List non-compliant targets
		for _, target := range result.Run.Targets {
			if target.Evaluation.Status != "compliant" {
				fmt.Printf("  - %s: %s\n", target.Source.Ref, target.Evaluation.Status)
			}
		}
		return nil
	}
}

// OutputQuiet outputs minimal information for quiet mode
func (o *Output) OutputQuiet(result *grant.RunResponse) error {
	nonCompliantCount := 0
	for _, target := range result.Run.Targets {
		if target.Evaluation.Status != "compliant" {
			nonCompliantCount++
		}
	}
	
	if nonCompliantCount > 0 {
		fmt.Printf("%d\n", nonCompliantCount)
	}
	return nil
}