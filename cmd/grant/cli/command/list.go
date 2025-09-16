package command

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/gookit/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"

	"github.com/anchore/grant/cmd/grant/cli/internal"
	"github.com/anchore/grant/grant"
)

// List creates the list command
func List() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list TARGET [LICENSE...]",
		Short: "List licenses found in one or more targets",
		Long: `List shows all licenses found in container images, SBOMs, filesystems, and files
without applying policy evaluation.

Targets can be:
- Container images: alpine:latest, ubuntu:22.04
- SBOM files: path/to/sbom.json, path/to/sbom.xml
- Directories: dir:./project, ./my-app
- Archive files: project.tar.gz, source.zip
- License files: LICENSE, COPYING
- Stdin: - (reads SBOM from stdin)

License filtering:
If license names are provided as additional arguments, only packages with those
specific licenses will be shown. For example:
  grant list dir:. "MIT" "Apache-2.0"

This command always returns exit code 0 unless there are processing errors.`,
		Args: cobra.MinimumNArgs(1),
		RunE: runList,
	}

	// Add command-specific flags
	cmd.Flags().Bool("disable-file-search", false, "disable filesystem license file search")
	cmd.Flags().Bool("licenses-only", false, "show only license information, not packages")
	cmd.Flags().Bool("packages-only", false, "show only package information, not licenses")
	cmd.Flags().String("pkg", "", "show detailed information for a specific package (requires license filter)")

	return cmd
}

// runList executes the list command
func runList(cmd *cobra.Command, args []string) error {
	// Parse arguments: first is target, rest are license filters
	target := args[0]
	var licenseFilters []string
	if len(args) > 1 {
		licenseFilters = args[1:]
	}

	// Check if input is grant JSON from stdin
	if grantResult, isGrantJSON := isGrantJSONInput(target); isGrantJSON {
		// Handle grant JSON input directly
		result := handleGrantJSONInput(grantResult, licenseFilters)

		// Get global configuration for output handling
		globalConfig := GetGlobalConfig(cmd)

		// Get command-specific flags for compatibility
		licensesOnly, _ := cmd.Flags().GetBool("licenses-only")
		packagesOnly, _ := cmd.Flags().GetBool("packages-only")
		packageDetail, _ := cmd.Flags().GetString("pkg")

		// Handle package detail view if specified
		if packageDetail != "" {
			// Validate that license filters are provided
			if len(licenseFilters) == 0 {
				return fmt.Errorf("--pkg flag requires license filter arguments")
			}

			// Filter to show only the specified package
			result = filterResultByPackage(result, packageDetail)

			// Show detailed package information instead of normal output
			return handlePackageDetailOutput(result, packageDetail, globalConfig)
		}

		// Handle filtered output
		if licensesOnly || packagesOnly {
			return handleFilteredOutput(result, globalConfig.OutputFormat, licensesOnly, packagesOnly, globalConfig.Quiet, globalConfig.OutputFile)
		}

		// Handle output
		if globalConfig.Quiet {
			// Handle output file if specified in quiet mode
			if globalConfig.OutputFile != "" {
				output := internal.NewOutput()
				if err := output.OutputJSON(result, globalConfig.OutputFile); err != nil {
					HandleError(fmt.Errorf("failed to write output file: %w", err), globalConfig.Quiet)
					return err
				}
			}
			handleListQuietOutput(result)
			return nil
		}

		// Handle output file if specified
		if globalConfig.OutputFile != "" {
			output := internal.NewOutput()
			if err := output.OutputJSON(result, globalConfig.OutputFile); err != nil {
				HandleError(fmt.Errorf("failed to write output file: %w", err), globalConfig.Quiet)
				return err
			}
		}

		// Normal output - use list-specific formatting for table output
		if globalConfig.OutputFormat == "table" {
			output := internal.NewOutput()
			if err := outputListTableWithFilters(output, result, licenseFilters); err != nil {
				HandleError(fmt.Errorf("failed to output result: %w", err), globalConfig.Quiet)
				return err
			}
		} else {
			if err := OutputResult(result, globalConfig.OutputFormat, globalConfig.OutputFile); err != nil {
				HandleError(fmt.Errorf("failed to output result: %w", err), globalConfig.Quiet)
				return err
			}
		}

		return nil
	}

	// Get global configuration
	globalConfig := GetGlobalConfig(cmd)

	// Get command-specific flags
	disableFileSearch, _ := cmd.Flags().GetBool("disable-file-search")
	licensesOnly, _ := cmd.Flags().GetBool("licenses-only")
	packagesOnly, _ := cmd.Flags().GetBool("packages-only")
	packageDetail, _ := cmd.Flags().GetString("pkg")

	// Load policy (needed for orchestrator, but not used for evaluation)
	policy, err := LoadPolicyFromConfig(globalConfig)
	if err != nil {
		HandleError(err, globalConfig.Quiet)
		return err
	}

	// Create orchestrator with configuration
	caseConfig := grant.CaseConfig{
		DisableFileSearch: disableFileSearch,
	}

	orchestrator, err := grant.NewOrchestratorWithConfig(policy, caseConfig)
	if err != nil {
		HandleError(fmt.Errorf("failed to create orchestrator: %w", err), globalConfig.Quiet)
		return err
	}
	defer orchestrator.Close()

	// Build argv for the response
	argv := append([]string{"grant", "list"}, target)
	if globalConfig.ConfigFile != "" {
		argv = append([]string{"grant", "list", "-c", globalConfig.ConfigFile}, target)
	}

	// Perform list
	result, err := orchestrator.List(argv, target)
	if err != nil {
		HandleError(fmt.Errorf("list failed: %w", err), globalConfig.Quiet)
		return err
	}

	// Apply license filtering if specified
	if len(licenseFilters) > 0 {
		result = filterResultByLicenses(result, licenseFilters)
	}

	// Handle package detail view if specified
	if packageDetail != "" {
		// Validate that license filters are provided
		if len(licenseFilters) == 0 {
			return fmt.Errorf("--pkg flag requires license filter arguments")
		}

		// Filter to show only the specified package
		result = filterResultByPackage(result, packageDetail)

		// Show detailed package information instead of normal output
		return handlePackageDetailOutput(result, packageDetail, globalConfig)
	}

	// Handle filtered output
	if licensesOnly || packagesOnly {
		return handleFilteredOutput(result, globalConfig.OutputFormat, licensesOnly, packagesOnly, globalConfig.Quiet, globalConfig.OutputFile)
	}

	// Handle output
	if globalConfig.Quiet {
		// Handle output file if specified in quiet mode
		if globalConfig.OutputFile != "" {
			output := internal.NewOutput()
			if err := output.OutputJSON(result, globalConfig.OutputFile); err != nil {
				HandleError(fmt.Errorf("failed to write output file: %w", err), globalConfig.Quiet)
				return err
			}
		}
		handleListQuietOutput(result)
		return nil
	}

	// Handle output file if specified
	if globalConfig.OutputFile != "" {
		output := internal.NewOutput()
		if err := output.OutputJSON(result, globalConfig.OutputFile); err != nil {
			HandleError(fmt.Errorf("failed to write output file: %w", err), globalConfig.Quiet)
			return err
		}
	}

	// Normal output - use list-specific formatting for table output
	if globalConfig.OutputFormat == "table" {
		output := internal.NewOutput()
		if err := outputListTableWithFilters(output, result, licenseFilters); err != nil {
			HandleError(fmt.Errorf("failed to output result: %w", err), globalConfig.Quiet)
			return err
		}
	} else {
		if err := OutputResult(result, globalConfig.OutputFormat, globalConfig.OutputFile); err != nil {
			HandleError(fmt.Errorf("failed to output result: %w", err), globalConfig.Quiet)
			return err
		}
	}

	return nil
}

// handleFilteredOutput handles licenses-only or packages-only output
func handleFilteredOutput(result *grant.RunResponse, format string, licensesOnly, packagesOnly bool, quiet bool, outputFile string) error {
	// If output file is specified, always write JSON to file
	if outputFile != "" {
		output := internal.NewOutput()
		if err := output.OutputJSON(result, outputFile); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
	}

	if format == "json" {
		// If no output file specified, write JSON to stdout
		if outputFile == "" {
			return OutputResult(result, format, "")
		}
		// If output file is specified, we already wrote to file, so no stdout output
		return nil
	}

	// For table format, show filtered information
	if licensesOnly {
		return showLicensesOnly(result, quiet)
	}

	if packagesOnly {
		return showPackagesOnly(result, quiet)
	}

	return nil
}

// showLicensesOnly shows only license information
func showLicensesOnly(result *grant.RunResponse, quiet bool) error {
	licenseMap := make(map[string]int) // license -> count

	for _, target := range result.Run.Targets {
		for _, pkg := range target.Evaluation.Findings.Packages {
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

	if quiet {
		// In quiet mode, just output license count
		fmt.Printf("%d\n", len(licenseMap))
		return nil
	}

	fmt.Printf("Licenses found (%d unique):\n", len(licenseMap))
	for license, count := range licenseMap {
		if count == 1 {
			fmt.Printf("  %s\n", license)
		} else {
			fmt.Printf("  %s (%d packages)\n", license, count)
		}
	}

	return nil
}

// showPackagesOnly shows only package information
func showPackagesOnly(result *grant.RunResponse, quiet bool) error {
	totalPackages := 0
	for _, target := range result.Run.Targets {
		totalPackages += len(target.Evaluation.Findings.Packages)
	}

	if quiet {
		// In quiet mode, just output package count
		fmt.Printf("%d\n", totalPackages)
		return nil
	}

	fmt.Printf("Packages found (%d total):\n", totalPackages)
	for _, target := range result.Run.Targets {
		if len(result.Run.Targets) > 1 {
			fmt.Printf("  Target: %s\n", target.Source.Ref)
		}

		for _, pkg := range target.Evaluation.Findings.Packages {
			version := pkg.Version
			if version == "" {
				version = "(no version)"
			}
			fmt.Printf("    %s@%s (%s)\n", pkg.Name, version, pkg.Type)
		}
	}

	return nil
}

// handleListQuietOutput handles quiet mode output for list
func handleListQuietOutput(result *grant.RunResponse) {
	// In quiet mode for list, output total number of unique licenses found
	licenseMap := make(map[string]bool)

	for _, target := range result.Run.Targets {
		for _, pkg := range target.Evaluation.Findings.Packages {
			for _, license := range pkg.Licenses {
				licenseKey := license.ID
				if licenseKey == "" {
					licenseKey = license.Name
				}
				if licenseKey != "" {
					licenseMap[licenseKey] = true
				}
			}
		}
	}

	fmt.Printf("%d\n", len(licenseMap))
}

// filterResultByLicenses filters the result to only include packages that have licenses matching the specified filters
func filterResultByLicenses(result *grant.RunResponse, licenseFilters []string) *grant.RunResponse {
	// Create a map for faster license lookup
	filterMap := make(map[string]bool)
	for _, filter := range licenseFilters {
		filterMap[filter] = true
	}

	// Create a new result with filtered packages
	filteredResult := &grant.RunResponse{
		Tool:    result.Tool,
		Version: result.Version,
		Run: grant.RunDetails{
			Argv:    result.Run.Argv,
			Policy:  result.Run.Policy,
			Targets: []grant.TargetResult{},
		},
	}

	for _, target := range result.Run.Targets {
		filteredPackages := []grant.PackageFinding{}
		matchedLicenses := make(map[string]bool)

		// Filter packages that have any of the specified licenses
		for _, pkg := range target.Evaluation.Findings.Packages {
			hasMatchingLicense := false
			for _, license := range pkg.Licenses {
				licenseKey := license.ID
				if licenseKey == "" {
					licenseKey = license.Name
				}
				if filterMap[licenseKey] {
					hasMatchingLicense = true
					matchedLicenses[licenseKey] = true
				}
			}
			if hasMatchingLicense {
				filteredPackages = append(filteredPackages, pkg)
			}
		}

		// Create filtered target with updated summary
		filteredTarget := grant.TargetResult{
			Source: target.Source,
			Evaluation: grant.TargetEvaluation{
				Status: target.Evaluation.Status,
				Summary: grant.EvaluationSummaryJSON{
					Packages: grant.PackageSummary{
						Total:      len(filteredPackages),
						Unlicensed: 0, // Will be calculated if needed
						Allowed:    len(filteredPackages), // All filtered packages are "allowed" for display
						Denied:     0,
						Ignored:    0,
					},
					Licenses: grant.LicenseSummary{
						Unique:  len(matchedLicenses),
						Allowed: len(matchedLicenses),
						Denied:  0,
						NonSPDX: 0, // Would need to calculate if needed
					},
				},
				Findings: grant.EvaluationFindings{
					Packages: filteredPackages,
				},
			},
		}

		filteredResult.Run.Targets = append(filteredResult.Run.Targets, filteredTarget)
	}

	return filteredResult
}

// outputListTableWithFilters outputs the list table with filter information
func outputListTableWithFilters(output *internal.Output, result *grant.RunResponse, licenseFilters []string) error {
	for _, target := range result.Run.Targets {
		if err := outputListTargetTableWithFilters(output, target, licenseFilters); err != nil {
			return err
		}
		fmt.Println() // Add spacing between targets
	}
	return nil
}

// outputListTargetTableWithFilters outputs a single target in list format with filter information
func outputListTargetTableWithFilters(output *internal.Output, target grant.TargetResult, licenseFilters []string) error {
	// Display progress steps
	fmt.Printf(" %s Loaded %s                                                                              %s\n",
		color.Green.Sprint("✔"),
		target.Source.Ref,
		target.Source.Type)

	fmt.Printf(" %s License listing\n", color.Green.Sprint("✔"))

	// Show filter applied if license filters are specified
	if len(licenseFilters) > 0 {
		var filterDisplay string
		if len(licenseFilters) == 1 {
			filterDisplay = fmt.Sprintf("[license=\"%s\"]", licenseFilters[0])
		} else {
			filterDisplay = fmt.Sprintf("[licenses=\"%s\"]", strings.Join(licenseFilters, "\", \""))
		}
		fmt.Printf(" %s Filter applied                     %s\n",
			color.Green.Sprint("✔"),
			filterDisplay)
	}

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

	// Show matched packages count if filtering is applied
	if len(licenseFilters) > 0 {
		matchedCount := len(target.Evaluation.Findings.Packages)
		fmt.Printf(" %s Matched packages                   [%d package",
			color.Green.Sprint("✔"),
			matchedCount)
		if matchedCount != 1 {
			fmt.Print("s")
		}
		fmt.Println("]")
	} else {
		// Display aggregated licenses section (only when not filtering)
		fmt.Printf(" %s Aggregated licenses                [grouped by license, desc by count]\n",
			color.Green.Sprint("✔"))
	}

	fmt.Println()

	// Display package table or aggregated license table
	if len(licenseFilters) > 0 {
		// Show packages with their licenses when filtering
		return printFilteredPackageTable(target.Evaluation.Findings.Packages)
	} else {
		// Create aggregated license table
		return printAggregatedLicenseTable(target.Evaluation.Findings.Packages)
	}
}

// printFilteredPackageTable prints packages that match license filters in a table format
func printFilteredPackageTable(packages []grant.PackageFinding) error {
	if len(packages) == 0 {
		fmt.Println("No packages found with the specified licenses.")
		return nil
	}

	// Sort packages alphabetically by name
	sort.Slice(packages, func(i, j int) bool {
		return packages[i].Name < packages[j].Name
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

	// Add rows for matching packages
	for _, pkg := range packages {
		// Format the licenses for this package
		licenses := formatLicenses(pkg.Licenses)
		version := pkg.Version
		if version == "" {
			version = "(no version)"
		}

		t.AppendRow(table.Row{
			pkg.Name,
			version,
			licenses,
		})
	}

	t.Render()
	return nil
}

// formatLicenses formats licenses for display
func formatLicenses(licenses []grant.LicenseDetail) string {
	if len(licenses) == 0 {
		return "(no licenses found)"
	}

	var licenseStrs []string
	for _, license := range licenses {
		licenseStr := license.ID
		if license.Name != "" && license.ID == "" {
			licenseStr = license.Name
		}
		if licenseStr == "" {
			licenseStr = "(unknown)"
		}

		// Shorten long license strings (like sha256 hashes)
		if strings.HasPrefix(licenseStr, "sha256:") && len(licenseStr) > 20 {
			licenseStr = "sha256:" + licenseStr[7:15] + "..."
		}

		licenseStrs = append(licenseStrs, licenseStr)
	}

	// If there are many licenses, show count
	if len(licenseStrs) > 5 {
		return strings.Join(licenseStrs[:5], ", ") + fmt.Sprintf(" (+%d more)", len(licenseStrs)-5)
	}

	return strings.Join(licenseStrs, ", ")
}

// printAggregatedLicenseTable prints licenses grouped by license name with package counts
func printAggregatedLicenseTable(packages []grant.PackageFinding) error {
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

// filterResultByPackage filters the result to only include a specific package by name
func filterResultByPackage(result *grant.RunResponse, packageName string) *grant.RunResponse {
	// Create a new result with only the specified package
	filteredResult := &grant.RunResponse{
		Tool:    result.Tool,
		Version: result.Version,
		Run: grant.RunDetails{
			Argv:    result.Run.Argv,
			Policy:  result.Run.Policy,
			Targets: []grant.TargetResult{},
		},
	}

	for _, target := range result.Run.Targets {
		matchedPackages := []grant.PackageFinding{}

		// Filter packages by name
		for _, pkg := range target.Evaluation.Findings.Packages {
			if pkg.Name == packageName {
				matchedPackages = append(matchedPackages, pkg)
			}
		}

		// Create filtered target
		filteredTarget := grant.TargetResult{
			Source: target.Source,
			Evaluation: grant.TargetEvaluation{
				Status: target.Evaluation.Status,
				Summary: grant.EvaluationSummaryJSON{
					Packages: grant.PackageSummary{
						Total:      len(matchedPackages),
						Unlicensed: 0,
						Allowed:    len(matchedPackages),
						Denied:     0,
						Ignored:    0,
					},
					Licenses: grant.LicenseSummary{
						Unique:  0, // Will be calculated in display
						Allowed: 0,
						Denied:  0,
						NonSPDX: 0,
					},
				},
				Findings: grant.EvaluationFindings{
					Packages: matchedPackages,
				},
			},
		}

		filteredResult.Run.Targets = append(filteredResult.Run.Targets, filteredTarget)
	}

	return filteredResult
}

// handlePackageDetailOutput displays detailed information for a specific package
func handlePackageDetailOutput(result *grant.RunResponse, packageName string, globalConfig *GlobalConfig) error {
	// Handle output file if specified
	if globalConfig.OutputFile != "" {
		output := internal.NewOutput()
		if err := output.OutputJSON(result, globalConfig.OutputFile); err != nil {
			HandleError(fmt.Errorf("failed to write output file: %w", err), globalConfig.Quiet)
			return err
		}
	}

	// Handle quiet mode
	if globalConfig.Quiet {
		// In quiet mode, just output the number of matching packages
		totalPackages := 0
		for _, target := range result.Run.Targets {
			totalPackages += len(target.Evaluation.Findings.Packages)
		}
		fmt.Printf("%d\n", totalPackages)
		return nil
	}

	// Handle JSON format
	if globalConfig.OutputFormat == formatJSON {
		if globalConfig.OutputFile == "" {
			output := internal.NewOutput()
			return output.OutputJSON(result, "")
		}
		// Already written to file above
		return nil
	}

	// Display detailed package information in table format
	return displayPackageDetails(result, packageName)
}

// displayPackageDetails displays detailed information about the package
func displayPackageDetails(result *grant.RunResponse, packageName string) error {
	if len(result.Run.Targets) == 0 {
		fmt.Printf("No targets found.\n")
		return nil
	}

	target := result.Run.Targets[0]
	packages := target.Evaluation.Findings.Packages

	if len(packages) == 0 {
		fmt.Printf("Package '%s' not found.\n", packageName)
		return nil
	}

	// Display progress-style header
	fmt.Printf(" %s Loaded %s                                                                              %s\n",
		color.Green.Sprint("✔"),
		target.Source.Ref,
		target.Source.Type)

	fmt.Printf(" %s License listing\n", color.Green.Sprint("✔"))
	fmt.Printf(" %s Package details                    [package=\"%s\"]\n",
		color.Green.Sprint("✔"),
		packageName)

	fmt.Printf(" %s Found package instances           [%d instance",
		color.Green.Sprint("✔"),
		len(packages))
	if len(packages) != 1 {
		fmt.Print("s")
	}
	fmt.Println("]")

	fmt.Println()

	// Display detailed information for each package instance
	for i, pkg := range packages {
		if i > 0 {
			fmt.Println()
			fmt.Println(strings.Repeat("─", 80))
			fmt.Println()
		}

		fmt.Printf("Package Instance %d:\n", i+1)
		fmt.Printf("  Name:     %s\n", pkg.Name)
		fmt.Printf("  Version:  %s\n", pkg.Version)
		fmt.Printf("  Type:     %s\n", pkg.Type)
		fmt.Printf("  ID:       %s\n", pkg.ID)
		fmt.Printf("  Decision: %s\n", pkg.Decision)

		// Display licenses
		if len(pkg.Licenses) == 0 {
			fmt.Printf("  Licenses: (no licenses found)\n")
		} else {
			fmt.Printf("  Licenses: (%d license", len(pkg.Licenses))
			if len(pkg.Licenses) != 1 {
				fmt.Print("s")
			}
			fmt.Println(")")

			for j, license := range pkg.Licenses {
				fmt.Printf("    %d. License ID: %s\n", j+1, license.ID)
				if license.Name != "" {
					fmt.Printf("       License Name: %s\n", license.Name)
				}
				fmt.Printf("       OSI Approved: %t\n", license.IsOsiApproved)
				fmt.Printf("       Deprecated: %t\n", license.IsDeprecatedLicenseID)
				if license.DetailsURL != "" {
					fmt.Printf("       Details URL: %s\n", license.DetailsURL)
				}
				if len(license.Evidence) > 0 {
					fmt.Printf("       Evidence: %v\n", license.Evidence)
				}
			}
		}

		// Display locations
		if len(pkg.Locations) == 0 {
			fmt.Printf("  Locations: (no locations)\n")
		} else {
			fmt.Printf("  Locations: (%d location", len(pkg.Locations))
			if len(pkg.Locations) != 1 {
				fmt.Print("s")
			}
			fmt.Println(")")

			for j, location := range pkg.Locations {
				fmt.Printf("    %d. %s\n", j+1, location)
			}
		}
	}

	return nil
}
