package command

import (
	"fmt"
	
	"github.com/spf13/cobra"
	
	"github.com/anchore/grant/grant"
)

// List creates the list command
func List() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list [TARGET...]",
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

This command always returns exit code 0 unless there are processing errors.`,
		Args: cobra.MinimumNArgs(1),
		RunE: runList,
	}
	
	// Add command-specific flags
	cmd.Flags().Bool("disable-file-search", false, "disable filesystem license file search")
	cmd.Flags().Bool("licenses-only", false, "show only license information, not packages")
	cmd.Flags().Bool("packages-only", false, "show only package information, not licenses")
	
	return cmd
}

// runList executes the list command
func runList(cmd *cobra.Command, args []string) error {
	// Get global configuration
	globalConfig := GetGlobalConfig(cmd)
	
	// Get command-specific flags
	disableFileSearch, _ := cmd.Flags().GetBool("disable-file-search")
	licensesOnly, _ := cmd.Flags().GetBool("licenses-only")
	packagesOnly, _ := cmd.Flags().GetBool("packages-only")
	
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
	argv := append([]string{"grant", "list"}, args...)
	if globalConfig.ConfigFile != "" {
		argv = append([]string{"grant", "list", "-c", globalConfig.ConfigFile}, args...)
	}
	
	// Perform list
	result, err := orchestrator.List(argv, args...)
	if err != nil {
		HandleError(fmt.Errorf("list failed: %w", err), globalConfig.Quiet)
		return err
	}
	
	// Handle filtered output
	if licensesOnly || packagesOnly {
		return handleFilteredOutput(result, globalConfig.OutputFormat, licensesOnly, packagesOnly, globalConfig.Quiet)
	}
	
	// Handle output
	if globalConfig.Quiet {
		return handleListQuietOutput(result)
	}
	
	// Normal output
	if err := OutputResult(result, globalConfig.OutputFormat); err != nil {
		HandleError(fmt.Errorf("failed to output result: %w", err), globalConfig.Quiet)
		return err
	}
	
	return nil
}

// handleFilteredOutput handles licenses-only or packages-only output
func handleFilteredOutput(result *grant.RunResponse, format string, licensesOnly, packagesOnly bool, quiet bool) error {
	if format == "json" {
		// For JSON, we would need to filter the result structure
		// For now, output the full result and let users filter with jq
		return OutputResult(result, format)
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
func handleListQuietOutput(result *grant.RunResponse) error {
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
	return nil
}