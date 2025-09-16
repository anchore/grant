package command

import (
	"fmt"
	"os"
	"sort"

	"github.com/gookit/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"

	"github.com/anchore/grant/cmd/grant/cli/internal"
	"github.com/anchore/grant/grant"
)

type checkFlags struct {
	DisableFileSearch bool
	Summary           bool
	Unlicensed        bool
	DryRun            bool
}

const (
	statusNonCompliant = "noncompliant"
	statusError        = "error"
)

// Check creates the check command
func Check() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check [TARGET...]",
		Short: "Check license compliance for one or more targets",
		Long: `Check evaluates license compliance for container images, SBOMs, filesystems, and files.

Targets can be:
- Container images: alpine:latest, ubuntu:22.04
- SBOM files: path/to/sbom.json, path/to/sbom.json
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
	cmd.Flags().Bool("summary", false, "show only summary information")
	cmd.Flags().Bool("unlicensed", false, "show only packages without licenses")
	cmd.Flags().Bool("dry-run", false, "run check without returning non-zero exit code on violations")

	return cmd
}

// runCheck executes the check command
func runCheck(cmd *cobra.Command, args []string) error {
	globalConfig := GetGlobalConfig(cmd)
	flags := parseCheckFlags(cmd)

	// Check if input is grant JSON from stdin
	if len(args) > 0 {
		if grantResult, isGrantJSON := isGrantJSONInput(args[0]); isGrantJSON {
			// Handle grant JSON input directly
			result := handleGrantJSONInput(grantResult, []string{}) // No license filters for check
			return handleCheckOutput(result, globalConfig, flags)
		}
	}

	realtimeUI := setupRealtimeUI(globalConfig, args)
	orchestrator, err := setupOrchestrator(globalConfig, flags.DisableFileSearch)
	if err != nil {
		return err
	}
	defer orchestrator.Close()

	result, err := performCheck(orchestrator, globalConfig, args)
	if err != nil {
		return err
	}

	updateUIWithResults(realtimeUI, result, args)
	return handleCheckOutput(result, globalConfig, flags)
}

// parseCheckFlags extracts and validates command-specific flags
func parseCheckFlags(cmd *cobra.Command) *checkFlags {
	disableFileSearch, _ := cmd.Flags().GetBool("disable-file-search")
	summary, _ := cmd.Flags().GetBool("summary")
	unlicensed, _ := cmd.Flags().GetBool("unlicensed")
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	return &checkFlags{
		DisableFileSearch: disableFileSearch,
		Summary:           summary,
		Unlicensed:        unlicensed,
		DryRun:            dryRun,
	}
}

// setupRealtimeUI initializes the real-time UI for progress display
func setupRealtimeUI(globalConfig *GlobalConfig, args []string) *internal.RealtimeUI {
	if globalConfig.Quiet || globalConfig.OutputFormat != formatTable {
		return nil
	}

	realtimeUI := internal.NewRealtimeUI(globalConfig.Quiet)
	if len(args) > 0 {
		realtimeUI.ShowLoadingProgress(args[0])
	}
	return realtimeUI
}

// setupOrchestrator creates and configures the orchestrator
func setupOrchestrator(globalConfig *GlobalConfig, disableFileSearch bool) (*grant.Orchestrator, error) {
	policy, err := LoadPolicyFromConfig(globalConfig)
	if err != nil {
		HandleError(err, globalConfig.Quiet)
		return nil, err
	}

	caseConfig := grant.CaseConfig{
		DisableFileSearch: disableFileSearch,
	}

	orchestrator, err := grant.NewOrchestratorWithConfig(policy, caseConfig)
	if err != nil {
		HandleError(fmt.Errorf("failed to create orchestrator: %w", err), globalConfig.Quiet)
		return nil, err
	}

	return orchestrator, nil
}

// performCheck executes the license compliance check
func performCheck(orchestrator *grant.Orchestrator, globalConfig *GlobalConfig, args []string) (*grant.RunResponse, error) {
	argv := append([]string{"grant", "check"}, args...)
	if globalConfig.ConfigFile != "" {
		argv = append([]string{"grant", "check", "-c", globalConfig.ConfigFile}, args...)
	}

	result, err := orchestrator.Check(argv, args...)
	if err != nil {
		HandleError(fmt.Errorf("check failed: %w", err), globalConfig.Quiet)
		return nil, err
	}

	return result, nil
}

// updateUIWithResults updates the real-time UI with check results
func updateUIWithResults(realtimeUI *internal.RealtimeUI, result *grant.RunResponse, args []string) {
	if realtimeUI == nil || len(result.Run.Targets) == 0 {
		return
	}

	target := result.Run.Targets[0]
	// Show scan complete status
	sourceRef := target.Source.Ref
	if len(args) > 0 {
		sourceRef = args[0]
	}
	realtimeUI.ShowScanComplete(sourceRef, target.Source.Type)

	// Show cataloged contents tree
	realtimeUI.ShowCatalogedContents(
		target.Evaluation.Summary.Packages.Total,
		target.Evaluation.Summary.Licenses.Unique,
		len(target.Evaluation.Findings.Packages),
	)
}

// handleCheckOutput processes and displays the check results
func handleCheckOutput(result *grant.RunResponse, globalConfig *GlobalConfig, flags *checkFlags) error {
	if globalConfig.Quiet {
		// Handle output file if specified in quiet mode
		if globalConfig.OutputFile != "" {
			output := internal.NewOutput()
			if err := output.OutputJSON(result, globalConfig.OutputFile); err != nil {
				HandleError(fmt.Errorf("failed to write output file: %w", err), globalConfig.Quiet)
				return err
			}
		}
		handleQuietOutput(result, flags.DryRun)
		return nil
	}

	if flags.Summary {
		return handleSummaryOutput(result, globalConfig.OutputFormat, globalConfig.OutputFile, globalConfig.NoOutput)
	}

	if flags.Unlicensed {
		return handleUnlicensedOutput(result, globalConfig.OutputFormat, globalConfig.OutputFile, globalConfig.NoOutput)
	}

	// Write to file if specified
	if globalConfig.OutputFile != "" {
		output := internal.NewOutput()
		if err := output.OutputJSON(result, globalConfig.OutputFile); err != nil {
			HandleError(fmt.Errorf("failed to write output file: %w", err), globalConfig.Quiet)
			return err
		}
	}

	// Skip terminal output if no-output flag is set and output file is specified
	if globalConfig.NoOutput && globalConfig.OutputFile != "" {
		handleExitCode(result, flags.DryRun)
		return nil
	}

	// Output to terminal based on format
	if err := OutputResult(result, globalConfig.OutputFormat, ""); err != nil {
		HandleError(fmt.Errorf("failed to output result: %w", err), globalConfig.Quiet)
		return err
	}

	handleExitCode(result, flags.DryRun)
	return nil
}

// handleQuietOutput handles quiet mode output
func handleQuietOutput(result *grant.RunResponse, dryRun bool) {
	nonCompliantCount := 0
	errorCount := 0

	for _, target := range result.Run.Targets {
		switch target.Evaluation.Status {
		case statusNonCompliant:
			nonCompliantCount++
		case statusError:
			errorCount++
		}
	}

	if nonCompliantCount > 0 || errorCount > 0 {
		fmt.Printf("%d\n", nonCompliantCount+errorCount)
		if !dryRun {
			os.Exit(1)
		}
	}
}

// handleSummaryOutput handles summary-only output
func handleSummaryOutput(result *grant.RunResponse, format string, outputFile string, noOutput bool) error {
	// Write to file if specified
	if outputFile != "" {
		output := internal.NewOutput()
		if err := output.OutputJSON(result, outputFile); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
	}

	// Skip terminal output if no-output flag is set and output file is specified
	if noOutput && outputFile != "" {
		return nil
	}

	if format == formatJSON {
		// For JSON, output full result if no file was specified
		if outputFile == "" {
			output := internal.NewOutput()
			return output.OutputJSON(result, "")
		}
		return nil
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
		case statusNonCompliant:
			totalNonCompliant++
		case statusError:
			totalErrors++
		}
	}

	fmt.Printf("\nCheck Summary:\n")
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

// handleUnlicensedOutput handles unlicensed output
func handleUnlicensedOutput(result *grant.RunResponse, format string, outputFile string, noOutput bool) error {
	// For JSON, filter the result to only show packages without licenses
	filteredResult := result
	if format == formatJSON {
		filteredResult = filterResultForNoLicenses(result)
	}

	// Write to file if specified
	if outputFile != "" {
		output := internal.NewOutput()
		if err := output.OutputJSON(filteredResult, outputFile); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
	}

	// Skip terminal output if no-output flag is set and output file is specified
	if noOutput && outputFile != "" {
		return nil
	}

	if format == formatJSON {
		// For JSON, output filtered result if no file was specified
		if outputFile == "" {
			output := internal.NewOutput()
			return output.OutputJSON(filteredResult, "")
		}
		return nil
	}

	// For table format, use the same structure as default output
	for _, target := range result.Run.Targets {
		if err := outputTargetTableUnlicensed(target); err != nil {
			return err
		}
		fmt.Println() // Add spacing between targets
	}

	return nil
}

// outputTargetTableUnlicensed outputs a single target as a table, showing only packages without licenses
func outputTargetTableUnlicensed(target grant.TargetResult) error {
	// Print progress-style header
	fmt.Printf(" ✔ Checking %s                                                                             %s\n", target.Source.Ref, target.Source.Type)
	fmt.Printf(" ✔ License compliance check                                %s\n", formatStatus(target.Evaluation.Status))
	fmt.Println()

	// Filter to packages without licenses
	packagesWithoutLicenses := []grant.PackageFinding{}
	for _, pkg := range target.Evaluation.Findings.Packages {
		if len(pkg.Licenses) == 0 {
			packagesWithoutLicenses = append(packagesWithoutLicenses, pkg)
		}
	}

	// Print summary in grype/syft style
	fmt.Printf(" ✔ Scanned for packages without licenses     [%d found]\n", len(packagesWithoutLicenses))
	fmt.Println()

	// Print detailed table if there are packages without licenses
	if len(packagesWithoutLicenses) > 0 {
		return printPackageTableUnlicensed(packagesWithoutLicenses)
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
		return color.Green.Sprint("[compliant]")
	case "noncompliant":
		return color.Red.Sprint("[non-compliant]")
	case "error":
		return color.Red.Sprint("[error]")
	case "list":
		return color.Blue.Sprint("[list]")
	default:
		return fmt.Sprintf("[%s]", status)
	}
}

// printPackageTableUnlicensed prints packages without licenses in the same table format as default output
func printPackageTableUnlicensed(packages []grant.PackageFinding) error {
	if len(packages) == 0 {
		return nil
	}

	// Sort packages alphabetically by name (same as default behavior)
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

	// Use uppercase headers to match grype style
	t.AppendHeader(table.Row{"NAME", "VERSION", "LICENSE STATUS"})

	// Add rows for packages without licenses
	for _, pkg := range packages {
		version := pkg.Version
		if version == "" {
			version = noVersion
		}

		// For packages without licenses, show "(no licenses found)" in red
		problematicLicenses := color.Red.Sprint("(no licenses found)")

		t.AppendRow(table.Row{
			pkg.Name,
			version,
			problematicLicenses,
		})
	}

	// Use cleaner title format
	if len(packages) > 0 {
		fmt.Printf("\nPackages without licenses\n")
	}
	t.Render()
	return nil
}

// handleExitCode determines the appropriate exit code
func handleExitCode(result *grant.RunResponse, dryRun bool) {
	if dryRun {
		// In dry-run mode, don't exit with error code
		return
	}

	hasNonCompliant := false
	hasErrors := false

	for _, target := range result.Run.Targets {
		switch target.Evaluation.Status {
		case statusNonCompliant:
			hasNonCompliant = true
		case statusError:
			hasErrors = true
		}
	}

	if hasNonCompliant || hasErrors {
		os.Exit(1)
	}
}
