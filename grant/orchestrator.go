package grant

import (
	"fmt"
	"os"
)

// Orchestrator coordinates grant operations across multiple targets
type Orchestrator struct {
	Policy      *Policy
	CaseHandler *CaseHandler
}

// NewOrchestrator creates a new Orchestrator with the given policy
func NewOrchestrator(policy *Policy) (*Orchestrator, error) {
	if policy == nil {
		return nil, fmt.Errorf("policy cannot be nil")
	}

	caseHandler, err := NewCaseHandler()
	if err != nil {
		return nil, fmt.Errorf("failed to create case handler: %w", err)
	}

	return &Orchestrator{
		Policy:      policy,
		CaseHandler: caseHandler,
	}, nil
}

// NewOrchestratorWithConfig creates a new Orchestrator with the given policy and case config
func NewOrchestratorWithConfig(policy *Policy, config CaseConfig) (*Orchestrator, error) {
	if policy == nil {
		return nil, fmt.Errorf("policy cannot be nil")
	}

	caseHandler, err := NewCaseHandlerWithConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create case handler: %w", err)
	}

	return &Orchestrator{
		Policy:      policy,
		CaseHandler: caseHandler,
	}, nil
}

// Close cleans up resources used by the orchestrator
func (o *Orchestrator) Close() {
	if o.CaseHandler != nil {
		o.CaseHandler.Close()
	}
}

// Check evaluates multiple targets against the policy and returns a RunResponse
func (o *Orchestrator) Check(argv []string, targets ...string) (*RunResponse, error) {
	response := NewRunResponse(argv, o.Policy)

	for _, target := range targets {
		// Determine source type
		sourceType := DetermineSourceType(target)
		source := SourceInfo{
			Type: sourceType,
			Ref:  target,
		}

		// Create case for the target
		c, err := o.CaseHandler.determineRequestCase(target)
		if err != nil {
			// Add error result for this target
			response.AddTarget(source, TargetEvaluation{
				Status: "error",
				Summary: EvaluationSummaryJSON{
					Packages: PackageSummary{},
					Licenses: LicenseSummary{},
				},
				Findings: EvaluationFindings{
					Packages: []PackageFinding{},
				},
			})
			continue
		}

		// Evaluate the case
		evalResult, err := c.Evaluate(o.Policy)
		if err != nil {
			// Add error result for this target
			response.AddTarget(source, TargetEvaluation{
				Status: "error",
				Summary: EvaluationSummaryJSON{
					Packages: PackageSummary{},
					Licenses: LicenseSummary{},
				},
				Findings: EvaluationFindings{
					Packages: []PackageFinding{},
				},
			})
			continue
		}

		// Convert evaluation to target result
		targetEval := ConvertEvaluationToTarget(evalResult, o.Policy)
		response.AddTarget(source, targetEval)
	}

	return response, nil
}

// List returns license information for multiple targets without policy evaluation
func (o *Orchestrator) List(argv []string, targets ...string) (*RunResponse, error) {
	response := NewRunResponse(argv, o.Policy)

	for _, target := range targets {
		source := SourceInfo{
			Type: DetermineSourceType(target),
			Ref:  target,
		}

		targetEval := o.processListTarget(target)
		response.AddTarget(source, targetEval)
	}

	return response, nil
}

// processListTarget processes a single target for listing licenses
func (o *Orchestrator) processListTarget(target string) TargetEvaluation {
	c, err := o.CaseHandler.determineRequestCase(target)
	if err != nil {
		return createErrorTargetEvaluation()
	}

	licensePackages, licenses, packagesNoLicenses := c.GetLicenses()
	findings := buildListFindings(licensePackages, packagesNoLicenses)
	summary := buildListSummary(licensePackages, licenses, packagesNoLicenses)

	return TargetEvaluation{
		Status:   "list",
		Summary:  summary,
		Findings: findings,
	}
}

// createErrorTargetEvaluation creates a standard error response
func createErrorTargetEvaluation() TargetEvaluation {
	return TargetEvaluation{
		Status: "error",
		Summary: EvaluationSummaryJSON{
			Packages: PackageSummary{},
			Licenses: LicenseSummary{},
		},
		Findings: EvaluationFindings{
			Packages: []PackageFinding{},
		},
	}
}

// buildListFindings creates findings from license packages
func buildListFindings(licensePackages map[string][]*Package, packagesNoLicenses []Package) EvaluationFindings {
	findings := EvaluationFindings{
		Packages: []PackageFinding{},
	}

	for _, packages := range licensePackages {
		for _, pkg := range packages {
			finding := packageToFinding(*pkg, "list")
			findings.Packages = append(findings.Packages, finding)
		}
	}

	for _, pkg := range packagesNoLicenses {
		finding := packageToFinding(pkg, "list")
		findings.Packages = append(findings.Packages, finding)
	}

	return findings
}

// buildListSummary creates summary statistics for list operation
func buildListSummary(licensePackages map[string][]*Package, licenses map[string]License, packagesNoLicenses []Package) EvaluationSummaryJSON {
	totalPackages := len(packagesNoLicenses)
	for _, packages := range licensePackages {
		totalPackages += len(packages)
	}

	return EvaluationSummaryJSON{
		Packages: PackageSummary{
			Total:      totalPackages,
			Unlicensed: len(packagesNoLicenses),
		},
		Licenses: LicenseSummary{
			Unique: len(licenses),
		},
	}
}

// CheckWithDefaults performs a check with default policy
func CheckWithDefaults(targets ...string) (*RunResponse, error) {
	// Create a default deny-all policy
	policy := &Policy{
		Allow:               []string{},
		IgnorePackages:      []string{},
		RequireLicense:      true,
		RequireKnownLicense: false,
	}

	orchestrator, err := NewOrchestrator(policy)
	if err != nil {
		return nil, err
	}
	defer orchestrator.Close()

	argv := append([]string{"grant", "check"}, targets...)
	return orchestrator.Check(argv, targets...)
}

// LoadPolicyOrDefault loads a policy from file or returns a default policy
func LoadPolicyOrDefault(filename string) (*Policy, error) {
	if filename != "" {
		// Check if file exists
		if _, err := os.Stat(filename); err == nil {
			return LoadPolicyFromFile(filename)
		}
	}

	// Return default policy - deny all
	return &Policy{
		Allow:               []string{},
		IgnorePackages:      []string{},
		RequireLicense:      true,
		RequireKnownLicense: false,
	}, nil
}
