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
	"github.com/anchore/grant/internal/input"
	"github.com/anchore/grant/internal/spdxlicense"
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

// List creates the list command
func List() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list [TARGET] [LICENSE...]",
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

When no target is specified and stdin is available (piped input), grant will
automatically read from stdin. This allows usage like:
  syft -o json dir:. | grant list Apache-2.0

License filtering:
If license names are provided as additional arguments, only packages with those
specific licenses will be shown. For example:
  grant list dir:. "MIT" "Apache-2.0"
  syft -o json dir:. | grant list "MIT" "Apache-2.0"

This command always returns exit code 0 unless there are processing errors.`,
		Args: cobra.ArbitraryArgs,
		RunE: runList,
	}

	// Add command-specific flags
	cmd.Flags().Bool("disable-file-search", false, "disable filesystem license file search")
	cmd.Flags().Bool("unlicensed", false, "show only packages without licenses")
	cmd.Flags().String("pkg", "", "show detailed information for a specific package (requires license filter)")
	cmd.Flags().String("group-by", "", "group results by specified field (risk)")

	return cmd
}

// handleJSONInput processes grant JSON input from stdin
func handleJSONInput(cmd *cobra.Command, target string, licenseFilters []string) (*grant.RunResponse, bool, error) {
	if grantResult, isGrantJSON := isGrantJSONInput(target); isGrantJSON {
		result := handleGrantJSONInput(grantResult, licenseFilters)
		globalConfig := GetGlobalConfig(cmd)

		packageDetail, _ := cmd.Flags().GetString("pkg")
		if packageDetail != "" {
			if len(licenseFilters) == 0 {
				return nil, true, fmt.Errorf("--pkg flag requires license filter arguments")
			}
			result = filterResultByPackage(result, packageDetail)
			return result, true, displayPackageDetails(result, packageDetail)
		}

		if globalConfig.OutputFile != "" {
			output := internal.NewOutput()
			if err := output.OutputJSON(result, globalConfig.OutputFile); err != nil {
				return nil, true, fmt.Errorf("failed to write output file: %w", err)
			}
		}

		// Skip terminal output if no-output flag is set and output file is specified
		if globalConfig.NoOutput && globalConfig.OutputFile != "" {
			return result, true, nil
		}

		if globalConfig.OutputFormat == "table" {
			return result, true, outputListTableWithFilters(result, licenseFilters)
		} else {
			return result, true, OutputResult(result, globalConfig.OutputFormat, "")
		}
	}
	return nil, false, nil
}

// runList executes the list command
func runList(cmd *cobra.Command, args []string) error {
	// Parse arguments and prepare filters
	target, licenseFilters, err := parseListArgumentsWithStdin(cmd, args)
	if err != nil {
		return err
	}

	// Check if input is grant JSON from stdin
	if _, handled, err := handleJSONInput(cmd, target, licenseFilters); handled {
		if err != nil {
			HandleError(err, GetGlobalConfig(cmd).Quiet)
		}
		return err
	}

	// Get global configuration
	globalConfig := GetGlobalConfig(cmd)

	// Get command-specific flags
	disableFileSearch, _ := cmd.Flags().GetBool("disable-file-search")
	packageDetail, _ := cmd.Flags().GetString("pkg")
	groupBy, _ := cmd.Flags().GetString("group-by")

	// Create orchestrator and perform list operation
	result, err := performListOperation(target, licenseFilters, disableFileSearch, globalConfig)
	if err != nil {
		return err
	}

	// Apply license filtering if specified
	if len(licenseFilters) > 0 {
		result = filterGrantJSONByLicenses(result, licenseFilters)
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

	// Handle group-by risk view
	if groupBy == "risk" {
		return handleGroupByRiskOutput(result, globalConfig)
	}

	// Handle output based on configuration
	return handleListOutput(result, licenseFilters, globalConfig)
}

// performListOperation creates orchestrator and executes the list command
func performListOperation(target string, licenseFilters []string, disableFileSearch bool, globalConfig *GlobalConfig) (*grant.RunResponse, error) {
	// Load policy (needed for orchestrator, but not used for evaluation)
	policy, err := LoadPolicyFromConfig(globalConfig)
	if err != nil {
		HandleError(err, globalConfig.Quiet)
		return nil, err
	}

	// Create orchestrator with configuration
	caseConfig := grant.CaseConfig{
		DisableFileSearch: disableFileSearch,
	}

	orchestrator, err := grant.NewOrchestratorWithConfig(policy, caseConfig)
	if err != nil {
		HandleError(fmt.Errorf("failed to create orchestrator: %w", err), globalConfig.Quiet)
		return nil, err
	}
	defer orchestrator.Close()

	// Build argv for the response
	argv := []string{"grant", "list"}
	if globalConfig.ConfigFile != "" {
		argv = append(argv, "-c", globalConfig.ConfigFile)
	}
	argv = append(argv, target)
	// Include license filters in argv
	if len(licenseFilters) > 0 {
		argv = append(argv, licenseFilters...)
	}

	// Perform list
	result, err := orchestrator.List(argv, target)
	if err != nil {
		HandleError(fmt.Errorf("list failed: %w", err), globalConfig.Quiet)
		return nil, err
	}

	return result, nil
}

// parseListArgumentsWithStdin extracts target and license filters, defaulting to stdin when appropriate
func parseListArgumentsWithStdin(cmd *cobra.Command, args []string) (string, []string, error) {
	var target string
	var licenseFilters []string

	// Check if stdin is available
	hasStdin, err := input.IsStdinPipeOrRedirect()
	if err != nil {
		return "", nil, err
	}

	if len(args) == 0 {
		// No arguments provided
		if hasStdin {
			// Use stdin as target
			target = "-"
		} else {
			// No stdin and no arguments - error
			return "", nil, fmt.Errorf("no target specified and no input available on stdin")
		}
	} else {
		// At least one argument provided
		// Check if the first argument looks like a target or a license filter
		firstArg := args[0]

		// If stdin is available and first arg doesn't look like a target path/reference,
		// treat all args as license filters
		if hasStdin && !looksLikeTarget(firstArg) {
			target = "-"
			licenseFilters = args
		} else {
			// Traditional parsing: first arg is target, rest are filters
			target = firstArg
			if len(args) > 1 {
				licenseFilters = args[1:]
			}
		}
	}

	// Check if --unlicensed flag is set
	unlicensed, _ := cmd.Flags().GetBool("unlicensed")
	if unlicensed {
		licenseFilters = append(licenseFilters, "(no licenses found)")
	}

	return target, licenseFilters, nil
}

// looksLikeTarget checks if a string looks like a target (file path, directory, image reference, etc.)
// rather than a license name
func looksLikeTarget(s string) bool {
	// Check for explicit target prefixes
	if strings.HasPrefix(s, "dir:") || strings.HasPrefix(s, "file:") || strings.HasPrefix(s, "image:") {
		return true
	}

	// Check if it looks like a file path
	if strings.Contains(s, "/") || strings.Contains(s, "\\") || strings.HasSuffix(s, ".json") ||
		strings.HasSuffix(s, ".xml") || strings.HasSuffix(s, ".tar") || strings.HasSuffix(s, ".gz") ||
		strings.HasSuffix(s, ".zip") {
		return true
	}

	// Check if it looks like a Docker image reference
	if strings.Contains(s, ":") || strings.Contains(s, "@") {
		return true
	}

	// Check for single dash (stdin indicator)
	if s == "-" {
		return true
	}

	// Check if it's a file that exists
	if _, err := os.Stat(s); err == nil {
		return true
	}

	// Otherwise, assume it's a license filter
	return false
}

// handleListOutput manages all output modes for the list command
func handleListOutput(result *grant.RunResponse, licenseFilters []string, globalConfig *GlobalConfig) error {
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

	// Skip terminal output if no-output flag is set and output file is specified
	if globalConfig.NoOutput && globalConfig.OutputFile != "" {
		return nil
	}

	// Normal output - use list-specific formatting for table output
	if globalConfig.OutputFormat == "table" {
		if err := outputListTableWithFilters(result, licenseFilters); err != nil {
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

// outputListTableWithFilters outputs the list table with filter information
func outputListTableWithFilters(result *grant.RunResponse, licenseFilters []string) error {
	for _, target := range result.Run.Targets {
		if err := outputListTargetTableWithFilters(target, licenseFilters); err != nil {
			return err
		}
		if internal.IsTerminalOutput() {
			fmt.Println() // Add spacing between targets
		}
	}
	return nil
}

// outputListTargetTableWithFilters outputs a single target in list format with filter information
func outputListTargetTableWithFilters(target grant.TargetResult, licenseFilters []string) error {
	// Only show progress TUI if outputting to a terminal
	if internal.IsTerminalOutput() {
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
	}

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
	t.AppendHeader(table.Row{"NAME", "VERSION", "LICENSE", "RISK"})

	// Add rows for matching packages
	for _, pkg := range packages {
		// Format the licenses for this package
		licenses := formatLicenses(pkg.Licenses)
		risk := formatRisk(pkg.Licenses)
		version := pkg.Version
		if version == "" {
			version = noVersion
		}

		t.AppendRow(table.Row{
			pkg.Name,
			version,
			licenses,
			risk,
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
			licenseStr = unknownLicense
		}

		// Shorten long license strings (like sha256 hashes)
		if strings.HasPrefix(licenseStr, "sha256:") && len(licenseStr) > 20 {
			licenseStr = "sha256:" + licenseStr[7:15] + "..."
		}

		licenseStrs = append(licenseStrs, formatClickableLicense(licenseStr))
	}

	// Show max 2 licenses before showing (+n more)
	if len(licenseStrs) > 2 {
		return strings.Join(licenseStrs[:2], ", ") + fmt.Sprintf(" (+%d more)", len(licenseStrs)-2)
	}

	return strings.Join(licenseStrs, ", ")
}

// printAggregatedLicenseTable prints licenses grouped by license name with package counts
func printAggregatedLicenseTable(packages []grant.PackageFinding) error {
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
					licenseKey = unknownLicense
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

	// Skip terminal output if no-output flag is set and output file is specified
	if globalConfig.NoOutput && globalConfig.OutputFile != "" {
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

// handleGroupByRiskOutput handles the group-by risk view output
func handleGroupByRiskOutput(result *grant.RunResponse, globalConfig *GlobalConfig) error {
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
		// In quiet mode, just output the number of risk categories
		fmt.Printf("3\n") // High, Medium, Low
		return nil
	}

	// Skip terminal output if no-output flag is set and output file is specified
	if globalConfig.NoOutput && globalConfig.OutputFile != "" {
		return nil
	}

	// Handle JSON format
	if globalConfig.OutputFormat == formatJSON {
		if globalConfig.OutputFile == "" {
			output := internal.NewOutput()
			return output.OutputJSON(result, "")
		}
		return nil
	}

	// Display risk-grouped view in table format
	for _, target := range result.Run.Targets {
		if err := outputRiskGroupedTable(target); err != nil {
			return err
		}
		if internal.IsTerminalOutput() {
			fmt.Println() // Add spacing between targets
		}
	}

	return nil
}

// outputRiskGroupedTable outputs licenses grouped by risk category
func outputRiskGroupedTable(target grant.TargetResult) error {
	// Display progress-style header only if outputting to a terminal
	if internal.IsTerminalOutput() {
		fmt.Printf(" %s Loaded %s\n",
			color.Green.Sprint("✔"),
			target.Source.Ref)

		fmt.Printf(" %s License listing\n", color.Green.Sprint("✔"))
		fmt.Printf(" %s Aggregated by risk\n", color.Green.Sprint("✔"))
		fmt.Println()
	}

	// Create risk category aggregations
	type riskStats struct {
		licenses map[string]bool
		packages map[string]bool
	}

	riskCategories := map[string]*riskStats{
		"Strong Copyleft": {
			licenses: make(map[string]bool),
			packages: make(map[string]bool),
		},
		"Weak Copyleft": {
			licenses: make(map[string]bool),
			packages: make(map[string]bool),
		},
		"Permissive": {
			licenses: make(map[string]bool),
			packages: make(map[string]bool),
		},
	}

	// Process each package
	for _, pkg := range target.Evaluation.Findings.Packages {
		packageKey := pkg.Name + "@" + pkg.Version

		for _, license := range pkg.Licenses {
			licenseKey := license.ID
			if licenseKey == "" {
				licenseKey = license.Name
			}
			if licenseKey == "" {
				continue // Skip unknown licenses
			}

			// Get the risk category
			var categoryName string
			switch {
			case license.RiskCategory.IsHigh():
				categoryName = "Strong Copyleft"
			case license.RiskCategory.IsMedium():
				categoryName = "Weak Copyleft"
			case license.RiskCategory.IsLow():
				categoryName = "Permissive"
			default:
				continue // Skip uncategorized
			}

			// Add to the appropriate category
			riskCategories[categoryName].licenses[licenseKey] = true
			riskCategories[categoryName].packages[packageKey] = true
		}
	}

	// Create table
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)

	// Configure table style to match grype/syft style
	t.Style().Options.SeparateHeader = false
	t.Style().Options.DrawBorder = false
	t.Style().Options.SeparateColumns = false
	t.Style().Options.SeparateFooter = false
	t.Style().Options.SeparateRows = false

	// Set headers
	t.AppendHeader(table.Row{"RISK CATEGORY", "LICENSES", "PACKAGES"})

	// Add rows in order of risk severity
	categoryOrder := []string{"Strong Copyleft", "Weak Copyleft", "Permissive"}
	for _, category := range categoryOrder {
		stats := riskCategories[category]
		if len(stats.licenses) > 0 || len(stats.packages) > 0 {
			t.AppendRow(table.Row{
				category,
				len(stats.licenses),
				len(stats.packages),
			})
		}
	}

	t.Render()
	return nil
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

	// Display progress-style header only if outputting to a terminal
	if internal.IsTerminalOutput() {
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
	}

	// Display detailed information for each package instance
	for i, pkg := range packages {
		if i > 0 {
			fmt.Println()
			fmt.Println(strings.Repeat("─", 80))
			fmt.Println()
		}

		fmt.Printf("Name:     %s\n", pkg.Name)
		fmt.Printf("Version:  %s\n", pkg.Version)
		fmt.Printf("Type:     %s\n", pkg.Type)
		fmt.Printf("ID:       %s\n", pkg.ID)

		// Display licenses with new formatting
		if len(pkg.Licenses) == 0 {
			fmt.Printf("Licenses: (no licenses found)\n")
		} else {
			fmt.Printf("Licenses (%d):\n", len(pkg.Licenses))

			for _, license := range pkg.Licenses {
				// Use license ID or name as display name
				licenseName := license.ID
				if licenseName == "" {
					licenseName = license.Name
				}
				if licenseName == "" {
					licenseName = "(unknown)"
				}

				fmt.Println()
				// Format with bullet point and make license name clickable if we have a reference
				if license.Reference != "" {
					// Make it blue and underlined to indicate it's clickable
					fmt.Printf("• \x1b]8;;%s\x1b\\\x1b[34;4m%s\x1b[0m\x1b]8;;\x1b\\\n", license.Reference, licenseName)
				} else {
					fmt.Printf("• %s\n", licenseName)
				}
				fmt.Printf("  OSI Approved: %t | Deprecated: %t\n", license.IsOsiApproved, license.IsDeprecatedLicenseID)
				if len(license.Evidence) > 0 {
					fmt.Printf("  Evidence: %v\n", license.Evidence)
				}
			}
		}
	}

	return nil
}
