package internal

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gookit/color"
)

const (
	branch = "├──"
	end    = "└──"
)

// ProgressDisplay manages the progress output for grant operations
type ProgressDisplay struct {
	mu      sync.Mutex
	steps   []ProgressStep
	verbose bool
	started time.Time
}

// ProgressStep represents a single step in the progress display
type ProgressStep struct {
	Title       string
	Status      StepStatus
	SubSteps    []SubStep
	ShowSubTree bool
}

// SubStep represents a sub-step with tree display
type SubStep struct {
	Icon  string
	Title string
	Value string
}

// StepStatus represents the status of a progress step
type StepStatus int

const (
	StatusPending StepStatus = iota
	StatusRunning
	StatusComplete
	StatusError
)

// NewProgressDisplay creates a new progress display
func NewProgressDisplay(verbose bool) *ProgressDisplay {
	return &ProgressDisplay{
		verbose: verbose,
		started: time.Now(),
	}
}

// AddStep adds a new step to the progress display
func (p *ProgressDisplay) AddStep(title string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.steps = append(p.steps, ProgressStep{
		Title:  title,
		Status: StatusPending,
	})
}

// UpdateStep updates the status of a step
func (p *ProgressDisplay) UpdateStep(index int, status StepStatus) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if index >= 0 && index < len(p.steps) {
		p.steps[index].Status = status
	}
}

// SetSubSteps sets the sub-steps for a given step
func (p *ProgressDisplay) SetSubSteps(index int, subSteps []SubStep) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if index >= 0 && index < len(p.steps) {
		p.steps[index].SubSteps = subSteps
		p.steps[index].ShowSubTree = true
	}
}

// CompleteStep marks a step as complete
func (p *ProgressDisplay) CompleteStep(index int) {
	p.UpdateStep(index, StatusComplete)
}

// Display shows the current progress
func (p *ProgressDisplay) Display() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, step := range p.steps {
		p.displayStep(step)
	}
}

// displayStep displays a single step with its status
func (p *ProgressDisplay) displayStep(step ProgressStep) {
	statusIcon := p.getStatusIcon(step.Status)
	statusColor := p.getStatusColor(step.Status)

	// Display main step
	fmt.Printf(" %s %s\n", statusColor(statusIcon), step.Title)

	// Display sub-steps if available
	if step.ShowSubTree && len(step.SubSteps) > 0 {
		for i, sub := range step.SubSteps {
			connector := branch
			if i == len(step.SubSteps)-1 {
				connector = end
			}
			fmt.Printf("   %s %s %-30s %s\n", connector, statusColor(sub.Icon), sub.Title, sub.Value)
		}
	}
}

// getStatusIcon returns the icon for a given status
func (p *ProgressDisplay) getStatusIcon(status StepStatus) string {
	switch status {
	case StatusComplete:
		return "✔"
	case StatusRunning:
		return "⠋"
	case StatusError:
		return "✗"
	default:
		return "○"
	}
}

// getStatusColor returns the color function for a given status
func (p *ProgressDisplay) getStatusColor(status StepStatus) func(a ...interface{}) string {
	switch status {
	case StatusComplete:
		return color.Green.Sprint
	case StatusError:
		return color.Red.Sprint
	default:
		return color.Gray.Sprint
	}
}

// DisplayScanProgress displays progress for scanning operations similar to grype/syft
func DisplayScanProgress(source string, sourceType string) *ProgressDisplay {
	progress := NewProgressDisplay(false)

	// Add standard scanning steps
	progress.AddStep(fmt.Sprintf("Checking %s", source))
	progress.CompleteStep(0)

	progress.AddStep("License compliance check")
	progress.CompleteStep(1)

	progress.AddStep("Cataloged contents")
	progress.SetSubSteps(2, []SubStep{
		{Icon: "✔", Title: "Packages", Value: "[analyzing...]"},
		{Icon: "✔", Title: "Licenses", Value: "[analyzing...]"},
		{Icon: "✔", Title: "File metadata", Value: "[analyzing...]"},
	})
	progress.CompleteStep(2)

	return progress
}

// UpdateCatalogedContents updates the cataloged contents with actual values
func (p *ProgressDisplay) UpdateCatalogedContents(packages int, licenses int, files int) {
	subSteps := []SubStep{
		{Icon: "✔", Title: "Packages", Value: fmt.Sprintf("[%d packages]", packages)},
		{Icon: "✔", Title: "Licenses", Value: fmt.Sprintf("[%d licenses]", licenses)},
		{Icon: "✔", Title: "File metadata", Value: fmt.Sprintf("[%d locations]", files)},
	}
	p.SetSubSteps(2, subSteps)
}

// DisplaySummaryTree displays the summary in tree format
func DisplaySummaryTree(total int, denied int, allowed int, ignored int, unlicensed int) {
	fmt.Printf(" %s Scanned for license compliance     %s\n",
		color.Green.Sprint("✔"),
		color.Gray.Sprintf("[%d packages]", total))

	if denied > 0 || allowed > 0 || ignored > 0 || unlicensed > 0 {
		var parts []string
		if denied > 0 {
			parts = append(parts, fmt.Sprintf("%d denied", denied))
		}
		if allowed > 0 {
			parts = append(parts, fmt.Sprintf("%d allowed", allowed))
		}
		if ignored > 0 {
			parts = append(parts, fmt.Sprintf("%d ignored", ignored))
		}
		if unlicensed > 0 {
			parts = append(parts, fmt.Sprintf("%d unlicensed", unlicensed))
		}

		fmt.Printf("   %s by compliance: %s\n",
			color.Gray.Sprint("└──"),
			strings.Join(parts, ", "))
	}
}
