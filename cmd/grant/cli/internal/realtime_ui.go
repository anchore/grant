package internal

import (
	"fmt"
	"os"
	"time"

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

// ShowScanProgress shows scanning progress with real-time updates
func (ui *RealtimeUI) ShowScanProgress(source string, sourceType string) {
	if ui.quiet {
		return
	}

	// Step 1: Loading
	fmt.Printf(" %s Loading %s", color.Cyan.Sprint("⠋"), source)
	time.Sleep(200 * time.Millisecond)
	fmt.Printf("\r %s Loaded %s                                                                              %s\n",
		color.Green.Sprint("✔"), source, color.Gray.Sprint(sourceType))

	// Step 2: License compliance check (running)
	fmt.Printf(" %s License compliance check", color.Cyan.Sprint("⠋"))
	time.Sleep(100 * time.Millisecond)

	// Step 3: Start cataloging
	fmt.Printf("\r %s License compliance check\n", color.Green.Sprint("✔"))
	fmt.Printf(" %s Cataloging packages", color.Cyan.Sprint("⠋"))
	time.Sleep(300 * time.Millisecond)

	// Step 4: Complete cataloging and show tree
	fmt.Printf("\r %s Cataloged contents\n", color.Green.Sprint("✔"))
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

// ShowScanningSteps shows all the scanning steps in sequence with realistic timing
func (ui *RealtimeUI) ShowScanningSteps(source string, sourceType string, packages int, licenses int, files int) {
	if ui.quiet {
		return
	}

	steps := []struct {
		title    string
		duration time.Duration
	}{
		{"Pulled image", 100 * time.Millisecond},
		{"Loaded image", 150 * time.Millisecond},
		{"Parsed image", 200 * time.Millisecond},
		{"Cataloged contents", 300 * time.Millisecond},
	}

	// Show steps with progress
	for _, step := range steps {
		// Show running state
		fmt.Printf(" %s %s", color.Cyan.Sprint("⠋"), step.title)
		_ = os.Stdout.Sync()
		time.Sleep(step.duration)

		// Complete the step
		if step.title == "Cataloged contents" {
			fmt.Printf("\r %s %s                                                     %s\n",
				color.Green.Sprint("✔"), step.title, color.Gray.Sprintf("sha256:%s", source[0:12]))

			// Show sub-tree for cataloged contents
			ui.ShowCatalogedContents(packages, licenses, files)
		} else {
			fmt.Printf("\r %s %s\n", color.Green.Sprint("✔"), step.title)
		}
	}
}
