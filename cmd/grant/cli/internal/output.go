package internal

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/gookit/color"
	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/anchore/grant/grant"
	"github.com/anchore/grant/internal/spdxlicense"
)

const (
	statusCompliant = "compliant"
)

// formatClickableLicense formats a license name as a clickable blue link if SPDX reference is available
func formatClickableLicense(licenseName string) string {
	if spdxLicense, err := spdxlicense.GetLicenseByID(licenseName); err == nil && spdxLicense.Reference != "" {
		// Make it blue and clickable (no underline for table display)
		return fmt.Sprintf("\033]8;;%s\033\\\033[34m%s\033[0m\033]8;;\033\\", spdxLicense.Reference, licenseName)
	}
	// Return the license name as-is if no SPDX reference available
	return licenseName
}

// getHighestRisk returns the highest risk category from a list of licenses
func getHighestRisk(licenses []grant.LicenseDetail) spdxlicense.RiskCategory {
	highestRisk := spdxlicense.RiskCategoryUncategorized

	for _, license := range licenses {
		if license.RiskCategory.IsHigh() {
			return license.RiskCategory // Return immediately if we find high risk
		}
		if license.RiskCategory.IsMedium() && !highestRisk.IsHigh() {
			highestRisk = license.RiskCategory
		}
		if license.RiskCategory.IsLow() && highestRisk.IsUncategorized() {
			highestRisk = license.RiskCategory
		}
	}

	return highestRisk
}

// formatRisk formats the risk category for display, showing count if multiple
func formatRisk(licenses []grant.LicenseDetail) string {
	if len(licenses) == 0 {
		return ""
	}

	highestRisk := getHighestRisk(licenses)

	// Count how many licenses have different risk levels
	riskCounts := make(map[spdxlicense.RiskCategory]int)
	for _, license := range licenses {
		if license.RiskCategory != "" {
			riskCounts[license.RiskCategory]++
		}
	}

	// Format the risk display
	riskStr := ""
	switch {
	case highestRisk.IsHigh():
		riskStr = color.Red.Sprint("High")
	case highestRisk.IsMedium():
		riskStr = color.Yellow.Sprint("Medium")
	case highestRisk.IsLow():
		riskStr = color.Green.Sprint("Low")
	default:
		riskStr = color.Gray.Sprint("Unknown")
	}

	// Add count if there are multiple licenses with different risks
	totalOtherRisks := 0
	for risk, count := range riskCounts {
		if risk != highestRisk {
			totalOtherRisks += count
		}
	}

	if totalOtherRisks > 0 {
		riskStr += fmt.Sprintf(" (+%d more)", totalOtherRisks)
	}

	return riskStr
}

// Output handles different output formats for grant results
type Output struct{}

// NewOutput creates a new Output instance
func NewOutput() *Output {
	return &Output{}
}

// OutputJSON outputs the result as JSON
func (o *Output) OutputJSON(result *grant.RunResponse, outputFile string) error {
	var writer = os.Stdout

	if outputFile != "" {
		// #nosec G304 - outputFile is controlled by user via CLI flag
		file, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file %s: %w", outputFile, err)
		}
		defer func() {
			if err := file.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to close output file: %v\n", err)
			}
		}()
		writer = file
	}

	encoder := json.NewEncoder(writer)
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

// OutputListTable outputs the result as a list-specific table format with progress and aggregated licenses
func (o *Output) OutputListTable(result *grant.RunResponse) error {
	for _, target := range result.Run.Targets {
		if err := o.outputListTargetTable(target); err != nil {
			return err
		}
		fmt.Println() // Add spacing between targets
	}
	return nil
}

// outputTargetTable outputs a single target as a table
func (o *Output) outputTargetTable(target grant.TargetResult) error {
	// Always show the final compliance summary tree
	DisplaySummaryTree(
		target.Evaluation.Summary.Packages.Total,
		target.Evaluation.Summary.Packages.Denied,
		target.Evaluation.Summary.Packages.Allowed,
		target.Evaluation.Summary.Packages.Ignored,
		target.Evaluation.Summary.Packages.Unlicensed,
	)

	// Print detailed findings if there are packages
	if len(target.Evaluation.Findings.Packages) > 0 {
		fmt.Println() // Single newline before table
		return o.printPackageTable(target.Evaluation.Findings.Packages)
	}

	return nil
}

// outputListTargetTable outputs a single target in list format with progress and aggregated licenses
func (o *Output) outputListTargetTable(target grant.TargetResult) error {
	// Display progress steps
	fmt.Printf(" %s Loaded %s                                                                              %s\n",
		color.Green.Sprint("✔"),
		target.Source.Ref,
		target.Source.Type)

	fmt.Printf(" %s License listing\n", color.Green.Sprint("✔"))
	fmt.Printf(" %s Cataloged contents\n", color.Green.Sprint("✔"))

	// Display tree structure with counts
	fmt.Printf("   %s %s %-30s %s\n",
		"├──",
		color.Green.Sprint("✔"),
		"Packages",
		fmt.Sprintf("[%d packages]", target.Evaluation.Summary.Packages.Total))

	fmt.Printf("   %s %s %-30s %s\n",
		"├──",
		color.Green.Sprint("✔"),
		"Licenses",
		fmt.Sprintf("[%d unique]", target.Evaluation.Summary.Licenses.Unique))

	// Count total file locations across all packages
	totalLocations := 0
	for _, pkg := range target.Evaluation.Findings.Packages {
		totalLocations += len(pkg.Locations)
	}

	fmt.Printf("   %s %s %-30s %s\n",
		"└──",
		color.Green.Sprint("✔"),
		"File metadata",
		fmt.Sprintf("[%d locations]", totalLocations))

	// Display aggregated licenses section
	fmt.Printf(" %s Aggregated licenses                [grouped by license, desc by count]\n",
		color.Green.Sprint("✔"))

	fmt.Println()

	// Create aggregated license table
	return o.printAggregatedLicenseTable(target.Evaluation.Findings.Packages)
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

	// Create table with no borders (grype/syft style)
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)

	// Configure table style to match grype/syft
	t.Style().Options.SeparateHeader = false
	t.Style().Options.DrawBorder = false
	t.Style().Options.SeparateColumns = false
	t.Style().Options.SeparateFooter = false
	t.Style().Options.SeparateRows = false

	// Set headers with uppercase to match grype style
	t.AppendHeader(table.Row{"NAME", "VERSION", "LICENSE", "RISK"})

	// Add rows for denied packages only
	for _, pkg := range deniedPackages {
		// Only show the licenses that caused the denial
		problematicLicenses := o.formatProblematicLicenses(pkg.Licenses)
		risk := formatRisk(pkg.Licenses)
		version := pkg.Version
		if version == "" {
			version = "(no version)"
		}

		t.AppendRow(table.Row{
			pkg.Name,
			version,
			problematicLicenses,
			risk,
		})
	}

	// Remove the header - just render table directly
	t.Render()
	return nil
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

		// Format problematic licenses in red with hyperlinks
		if licenseStr == "" || licenseStr == "(none)" {
			problematic = append(problematic, color.Red.Sprint("(unknown)"))
		} else {
			// Check if we have an SPDX reference for the license
			if spdxLicense, err := spdxlicense.GetLicenseByID(licenseStr); err == nil && spdxLicense.Reference != "" {
				// Make it red and clickable
				problematic = append(problematic, fmt.Sprintf("\033]8;;%s\033\\\033[31m%s\033[0m\033]8;;\033\\", spdxLicense.Reference, licenseStr))
			} else {
				problematic = append(problematic, color.Red.Sprint(licenseStr))
			}
		}
	}

	if len(problematic) == 0 {
		return color.Red.Sprint("(no licenses found)")
	}

	// Show max 2 licenses before showing (+n more)
	if len(problematic) > 2 {
		return strings.Join(problematic[:2], ", ") + color.Gray.Sprintf(" (+%d more)", len(problematic)-2)
	}

	return strings.Join(problematic, ", ")
}

// OutputSummaryOnly outputs just the summary information
func (o *Output) OutputSummaryOnly(result *grant.RunResponse) error {
	totalCompliant := 0
	totalTargets := len(result.Run.Targets)

	for _, target := range result.Run.Targets {
		if target.Evaluation.Status == statusCompliant {
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
			if target.Evaluation.Status != statusCompliant {
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
		if target.Evaluation.Status != statusCompliant {
			nonCompliantCount++
		}
	}

	if nonCompliantCount > 0 {
		fmt.Printf("%d\n", nonCompliantCount)
	}
	return nil
}

// printAggregatedLicenseTable prints licenses grouped by license name with package counts
func (o *Output) printAggregatedLicenseTable(packages []grant.PackageFinding) error {
	// First, deduplicate packages by name@version
	uniquePackages := make(map[string]grant.PackageFinding)
	for _, pkg := range packages {
		packageKey := pkg.Name + "@" + pkg.Version
		uniquePackages[packageKey] = pkg
	}

	// Create license to unique packages map
	licensePackages := make(map[string]map[string]bool)

	for _, pkg := range uniquePackages {
		packageKey := pkg.Name + "@" + pkg.Version

		if len(pkg.Licenses) == 0 {
			// Package with no licenses
			if licensePackages["(no licenses found)"] == nil {
				licensePackages["(no licenses found)"] = make(map[string]bool)
			}
			licensePackages["(no licenses found)"][packageKey] = true
		} else {
			for _, license := range pkg.Licenses {
				licenseKey := license.ID
				if licenseKey == "" {
					licenseKey = license.Name
				}
				if licenseKey == "" {
					licenseKey = "(unknown)"
				}
				if licensePackages[licenseKey] == nil {
					licensePackages[licenseKey] = make(map[string]bool)
				}
				licensePackages[licenseKey][packageKey] = true
			}
		}
	}

	// Convert to count map
	licenseMap := make(map[string]int)
	for license, pkgSet := range licensePackages {
		licenseMap[license] = len(pkgSet)
	}

	// Convert to slice for sorting
	type licenseCount struct {
		license string
		count   int
	}

	var licenseCounts []licenseCount
	for license, count := range licenseMap {
		licenseCounts = append(licenseCounts, licenseCount{license, count})
	}

	// Sort by count descending, then by name ascending
	sort.Slice(licenseCounts, func(i, j int) bool {
		if licenseCounts[i].count == licenseCounts[j].count {
			return licenseCounts[i].license < licenseCounts[j].license
		}
		return licenseCounts[i].count > licenseCounts[j].count
	})

	// Create table
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)

	// Configure table style to match grype/syft style (consistent with other tables)
	t.Style().Options.SeparateHeader = false
	t.Style().Options.DrawBorder = false
	t.Style().Options.SeparateColumns = false
	t.Style().Options.SeparateFooter = false
	t.Style().Options.SeparateRows = false

	// Set headers
	t.AppendHeader(table.Row{"LICENSE", "PACKAGES", "RISK"})

	// Add rows
	for _, lc := range licenseCounts {
		// Get risk category for this license
		riskStr := color.Gray.Sprint("Unknown")
		if spdxLicense, err := spdxlicense.GetLicenseByID(lc.license); err == nil {
			switch {
			case spdxLicense.RiskCategory.IsHigh():
				riskStr = color.Red.Sprint("High")
			case spdxLicense.RiskCategory.IsMedium():
				riskStr = color.Yellow.Sprint("Medium")
			case spdxLicense.RiskCategory.IsLow():
				riskStr = color.Green.Sprint("Low")
			}
		}
		t.AppendRow(table.Row{formatClickableLicense(lc.license), lc.count, riskStr})
	}

	t.Render()
	return nil
}
