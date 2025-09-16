package internal

import (
	"fmt"

	"github.com/gookit/color"
)

// RealtimeUI provides a simpler real-time progress display
type RealtimeUI struct {
	quiet bool
}

// NewRealtimeUI creates a new real-time UI
func NewRealtimeUI(quiet bool) *RealtimeUI {
	return &RealtimeUI{quiet: quiet}
}

// ShowLoadingProgress shows initial loading message
func (ui *RealtimeUI) ShowLoadingProgress(source string) {
	if ui.quiet {
		return
	}

	// Show initial loading message without delay
	fmt.Printf(" %s Loading %s\n", color.Cyan.Sprint("⠋"), source)
}

// ShowScanComplete shows completed scan status
func (ui *RealtimeUI) ShowScanComplete(source string, sourceType string) {
	if ui.quiet {
		return
	}

	// Clear the loading line and show completion
	fmt.Printf("\033[1A") // Move cursor up one line
	fmt.Printf("\r %s Loaded %s                                                                              %s\n",
		color.Green.Sprint("✔"), source, color.Gray.Sprint(sourceType))
	fmt.Printf(" %s License listing\n", color.Green.Sprint("✔"))
	fmt.Printf(" %s Cataloged contents\n", color.Green.Sprint("✔"))
}

// ShowCatalogedContents shows the cataloged contents in tree format
func (ui *RealtimeUI) ShowCatalogedContents(packages int, licenses int, files int) {
	if ui.quiet {
		return
	}

	fmt.Printf("   %s %s %-30s %s\n",
		color.Gray.Sprint("├──"),
		color.Green.Sprint("✔"),
		"Packages",
		color.Gray.Sprintf("[%d packages]", packages))
	fmt.Printf("   %s %s %-30s %s\n",
		color.Gray.Sprint("├──"),
		color.Green.Sprint("✔"),
		"Licenses",
		color.Gray.Sprintf("[%d unique]", licenses))
	fmt.Printf("   %s %s %-30s %s\n",
		color.Gray.Sprint("└──"),
		color.Green.Sprint("✔"),
		"File metadata",
		color.Gray.Sprintf("[%d locations]", files))
}

// ShowComplianceResult shows the compliance check result
func (ui *RealtimeUI) ShowComplianceResult(status string) {
	if ui.quiet {
		return
	}

	fmt.Printf(" %s Scanned for vulnerabilities     %s\n",
		color.Green.Sprint("✔"), status)
}

// ShowScanningSteps shows all the scanning steps (deprecated - kept for compatibility)
func (ui *RealtimeUI) ShowScanningSteps(source string, sourceType string, packages int, licenses int, files int) {
	if ui.quiet {
		return
	}

	// This function is deprecated in favor of ShowLoadingProgress/ShowScanComplete
	// but kept for compatibility
	fmt.Printf(" %s Pulled image\n", color.Green.Sprint("✔"))
	fmt.Printf(" %s Loaded image\n", color.Green.Sprint("✔"))
	fmt.Printf(" %s Parsed image\n", color.Green.Sprint("✔"))
	fmt.Printf(" %s Cataloged contents                                                     %s\n",
		color.Green.Sprint("✔"), color.Gray.Sprintf("sha256:%s", source[0:12]))

	// Show sub-tree for cataloged contents
	ui.ShowCatalogedContents(packages, licenses, files)
}
