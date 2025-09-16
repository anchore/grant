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
)

const (
	statusCompliant = "compliant"
)

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
		file, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file %s: %w", outputFile, err)
		}
		defer file.Close()
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
	t.AppendHeader(table.Row{"NAME", "VERSION", "LICENSE"})

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
	// Create license count map
	licenseMap := make(map[string]int)

	for _, pkg := range packages {
		if len(pkg.Licenses) == 0 {
			// Package with no licenses
			licenseMap["(no licenses found)"]++
		} else {
			for _, license := range pkg.Licenses {
				licenseKey := license.ID
				if licenseKey == "" {
					licenseKey = license.Name
				}
				if licenseKey == "" {
					licenseKey = "(unknown)"
				}
				licenseMap[licenseKey]++
			}
		}
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

	// Configure table style to match the desired output
	t.Style().Options.SeparateHeader = false
	t.Style().Options.DrawBorder = false
	t.Style().Options.SeparateColumns = true
	t.Style().Options.SeparateFooter = false
	t.Style().Options.SeparateRows = false

	// Set headers
	t.AppendHeader(table.Row{"LICENSE", "PACKAGES"})

	// Add rows
	for _, lc := range licenseCounts {
		t.AppendRow(table.Row{lc.license, lc.count})
	}

	t.Render()
	return nil
}
