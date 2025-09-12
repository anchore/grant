package command

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/gookit/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"

	"github.com/anchore/grant/grant"
)

// Check creates the check command
func Check() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check [TARGET...]",
		Short: "Check license compliance for one or more targets",
		Long: `Check evaluates license compliance for container images, SBOMs, filesystems, and files.
		
Targets can be:
- Container images: alpine:latest, ubuntu:22.04
- SBOM files: path/to/sbom.json, path/to/sbom.xml  
- Directories: dir:./project, ./my-app
- Archive files: project.tar.gz, source.zip
- License files: LICENSE, COPYING
- Stdin: - (reads SBOM from stdin)

Exit codes:
- 0: All targets are compliant
- 1: One or more targets are non-compliant or an error occurred`,
		Args: cobra.MinimumNArgs(1),
		RunE: runCheck,
	}

	// Add command-specific flags
	cmd.Flags().Bool("disable-file-search", false, "disable filesystem license file search")
	cmd.Flags().Bool("fail-on-error", false, "fail immediately on first error")
	cmd.Flags().Bool("summary-only", false, "show only summary information")
	cmd.Flags().Bool("no-licenses-only", false, "show only packages without licenses")

	return cmd
}

// runCheck executes the check command
func runCheck(cmd *cobra.Command, args []string) error {
	// Get global configuration
	globalConfig := GetGlobalConfig(cmd)

	// Get command-specific flags
	disableFileSearch, _ := cmd.Flags().GetBool("disable-file-search")
	failOnError, _ := cmd.Flags().GetBool("fail-on-error")
	summaryOnly, _ := cmd.Flags().GetBool("summary-only")
	noLicensesOnly, _ := cmd.Flags().GetBool("no-licenses-only")

	// Load policy
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
	argv := append([]string{"grant", "check"}, args...)
	if globalConfig.ConfigFile != "" {
		argv = append([]string{"grant", "check", "-c", globalConfig.ConfigFile}, args...)
	}

	// Perform check
	result, err := orchestrator.Check(argv, args...)
	if err != nil {
		HandleError(fmt.Errorf("check failed: %w", err), globalConfig.Quiet)
		return err
	}

	// Handle output
	if globalConfig.Quiet {
		// In quiet mode, just output non-compliant count and set exit code
		return handleQuietOutput(result)
	}

	if summaryOnly {
		return handleSummaryOutput(result, globalConfig.OutputFormat)
	}

	if noLicensesOnly {
		return handleNoLicensesOnlyOutput(result, globalConfig.OutputFormat)
	}

	// Normal output
	if err := OutputResult(result, globalConfig.OutputFormat); err != nil {
		HandleError(fmt.Errorf("failed to output result: %w", err), globalConfig.Quiet)
		return err
	}

	// Set exit code based on compliance
	return handleExitCode(result, failOnError)
}

// handleQuietOutput handles quiet mode output
func handleQuietOutput(result *grant.RunResponse) error {
	nonCompliantCount := 0
	errorCount := 0

	for _, target := range result.Run.Targets {
		switch target.Evaluation.Status {
		case "noncompliant":
			nonCompliantCount++
		case "error":
			errorCount++
		}
	}

	if nonCompliantCount > 0 || errorCount > 0 {
		fmt.Printf("%d\n", nonCompliantCount+errorCount)
		os.Exit(1)
	}

	return nil
}

// handleSummaryOutput handles summary-only output
func handleSummaryOutput(result *grant.RunResponse, format string) error {
	if format == "json" {
		// For JSON, output full result but caller can filter
		return OutputResult(result, format)
	}

	// For table format, show summary only
	totalCompliant := 0
	totalNonCompliant := 0
	totalErrors := 0
	totalTargets := len(result.Run.Targets)

	for _, target := range result.Run.Targets {
		switch target.Evaluation.Status {
		case "compliant":
			totalCompliant++
		case "noncompliant":
			totalNonCompliant++
		case "error":
			totalErrors++
		}
	}

	fmt.Printf("Check Summary:\n")
	fmt.Printf("  Total targets: %d\n", totalTargets)
	if totalCompliant > 0 {
		fmt.Printf("  Compliant: %d\n", totalCompliant)
	}
	if totalNonCompliant > 0 {
		fmt.Printf("  Non-compliant: %d\n", totalNonCompliant)
	}
	if totalErrors > 0 {
		fmt.Printf("  Errors: %d\n", totalErrors)
	}

	if totalNonCompliant > 0 || totalErrors > 0 {
		fmt.Println("\nNon-compliant/Error targets:")
		for _, target := range result.Run.Targets {
			if target.Evaluation.Status == "noncompliant" || target.Evaluation.Status == "error" {
				fmt.Printf("  - %s: %s\n", target.Source.Ref, target.Evaluation.Status)
			}
		}
	}

	return nil
}

// handleNoLicensesOnlyOutput handles no-licenses-only output
func handleNoLicensesOnlyOutput(result *grant.RunResponse, format string) error {
	if format == "json" {
		// For JSON, filter the result to only show packages without licenses
		filteredResult := filterResultForNoLicenses(result)
		return OutputResult(filteredResult, format)
	}

	// For table format, use the same structure as default output
	for _, target := range result.Run.Targets {
		if err := outputTargetTableNoLicensesOnly(target); err != nil {
			return err
		}
		fmt.Println() // Add spacing between targets
	}

	return nil
}

// outputTargetTableNoLicensesOnly outputs a single target as a table, showing only packages without licenses
func outputTargetTableNoLicensesOnly(target grant.TargetResult) error {
	// Print target header
	fmt.Printf("Target: %s (%s)\n", target.Source.Ref, target.Source.Type)
	fmt.Printf("Status: %s\n", formatStatus(target.Evaluation.Status))
	fmt.Println()

	// Filter to packages without licenses
	packagesWithoutLicenses := []grant.PackageFinding{}
	for _, pkg := range target.Evaluation.Findings.Packages {
		if len(pkg.Licenses) == 0 {
			packagesWithoutLicenses = append(packagesWithoutLicenses, pkg)
		}
	}

	// Print summary focused on unlicensed packages
	fmt.Println("Summary:")
	fmt.Printf("  Packages without licenses: %d\n", len(packagesWithoutLicenses))
	fmt.Println()

	// Print detailed table if there are packages without licenses
	if len(packagesWithoutLicenses) > 0 {
		return printPackageTableNoLicensesOnly(packagesWithoutLicenses)
	} else {
		fmt.Println("No packages without licenses found.")
	}

	return nil
}

// filterResultForNoLicenses creates a filtered copy of the result with only packages without licenses
func filterResultForNoLicenses(result *grant.RunResponse) *grant.RunResponse {
	filtered := &grant.RunResponse{
		Tool:    result.Tool,
		Version: result.Version,
		Run: grant.RunDetails{
			Argv:    result.Run.Argv,
			Policy:  result.Run.Policy,
			Targets: []grant.TargetResult{},
		},
	}

	for _, target := range result.Run.Targets {
		packagesWithoutLicenses := []grant.PackageFinding{}
		unlicensedCount := 0

		for _, pkg := range target.Evaluation.Findings.Packages {
			if len(pkg.Licenses) == 0 {
				packagesWithoutLicenses = append(packagesWithoutLicenses, pkg)
				unlicensedCount++
			}
		}

		// Create filtered target with updated summary
		filteredTarget := grant.TargetResult{
			Source: target.Source,
			Evaluation: grant.TargetEvaluation{
				Status: target.Evaluation.Status,
				Summary: grant.EvaluationSummaryJSON{
					Packages: grant.PackageSummary{
						Total:      unlicensedCount,
						Unlicensed: unlicensedCount,
						Allowed:    0,
						Denied:     0,
						Ignored:    0,
					},
					Licenses: grant.LicenseSummary{
						Unique:  0,
						Allowed: 0,
						Denied:  0,
						NonSPDX: 0,
					},
				},
				Findings: grant.EvaluationFindings{
					Packages: packagesWithoutLicenses,
				},
			},
		}

		filtered.Run.Targets = append(filtered.Run.Targets, filteredTarget)
	}

	return filtered
}

// formatStatus formats the status with colors (copied from output.go)
func formatStatus(status string) string {
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

// printPackageTableNoLicensesOnly prints packages without licenses in the same table format as default output
func printPackageTableNoLicensesOnly(packages []grant.PackageFinding) error {
	if len(packages) == 0 {
		return nil
	}

	// Sort packages alphabetically by name (same as default behavior)
	sort.Slice(packages, func(i, j int) bool {
		return packages[i].Name < packages[j].Name
	})

	// Create table with same structure as default output
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleDefault)

	// Use the same headers as the default table
	t.AppendHeader(table.Row{"Package", "Version", "Problematic Licenses"})

	// Add rows for packages without licenses
	for _, pkg := range packages {
		version := pkg.Version
		if version == "" {
			version = "(no version)"
		}

		// For packages without licenses, show "(no licenses found)" in red
		problematicLicenses := color.Red.Sprint("(no licenses found)")

		t.AppendRow(table.Row{
			pkg.Name,
			version,
			problematicLicenses,
		})
	}

	// Use the same title format as default output
	fmt.Printf("Packages without licenses (%d):\n", len(packages))
	t.Render()
	return nil
}

// handleExitCode determines the appropriate exit code
func handleExitCode(result *grant.RunResponse, failOnError bool) error {
	hasNonCompliant := false
	hasErrors := false

	for _, target := range result.Run.Targets {
		switch target.Evaluation.Status {
		case "noncompliant":
			hasNonCompliant = true
		case "error":
			hasErrors = true
		}
	}

	if hasErrors && failOnError {
		os.Exit(1)
	}

	if hasNonCompliant || hasErrors {
		os.Exit(1)
	}

	return nil
}
