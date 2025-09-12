package grant

import "github.com/anchore/grant/internal"

// RunResponse represents the complete JSON response structure for grant operations
type RunResponse struct {
	Tool    string     `json:"tool"`
	Version string     `json:"version"`
	Run     RunDetails `json:"run"`
}

// RunDetails contains the execution details and results
type RunDetails struct {
	Argv    []string       `json:"argv"`
	Policy  PolicyConfig   `json:"policy"`
	Targets []TargetResult `json:"targets"`
}

// PolicyConfig represents the policy configuration used in the run
type PolicyConfig struct {
	Rules               PolicyRules `json:"rules"`
	RequireLicense      bool        `json:"requireLicense"`
	RequireKnownLicense bool        `json:"requireKnownLicense"`
}

// PolicyRules contains the allow and ignore rules
type PolicyRules struct {
	Allow          []string `json:"allow"`
	IgnorePackages []string `json:"ignorePackages"`
}

// TargetResult represents the evaluation result for a single target
type TargetResult struct {
	Source     SourceInfo       `json:"source"`
	Evaluation TargetEvaluation `json:"evaluation"`
}

// SourceInfo contains information about the source being evaluated
type SourceInfo struct {
	Type        string `json:"type"` // image | sbom | dir | file
	Ref         string `json:"ref"`
	ResolvedRef string `json:"resolvedRef,omitempty"`
}

// TargetEvaluation contains the evaluation results for a target
type TargetEvaluation struct {
	Status   string                `json:"status"` // compliant | noncompliant
	Summary  EvaluationSummaryJSON `json:"summary"`
	Findings EvaluationFindings    `json:"findings"`
}

// EvaluationSummaryJSON provides statistics about packages and licenses
type EvaluationSummaryJSON struct {
	Packages PackageSummary `json:"packages"`
	Licenses LicenseSummary `json:"licenses"`
}

// PackageSummary contains package statistics
type PackageSummary struct {
	Total      int `json:"total"`
	Allowed    int `json:"allowed"`
	Denied     int `json:"denied"`
	Ignored    int `json:"ignored"`
	Unlicensed int `json:"unlicensed"`
}

// LicenseSummary contains license statistics
type LicenseSummary struct {
	Unique  int `json:"unique"`
	Allowed int `json:"allowed"`
	Denied  int `json:"denied"`
	NonSPDX int `json:"nonSPDX"` // Non-SPDX license identifiers (may be custom or proprietary)
}

// EvaluationFindings contains the detailed findings
type EvaluationFindings struct {
	Packages []PackageFinding `json:"packages"`
}

// PackageFinding represents a single package finding
type PackageFinding struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Type      string          `json:"type"`
	Version   string          `json:"version"`
	Decision  string          `json:"decision"` // allow | deny | ignore
	Licenses  []LicenseDetail `json:"licenses"`
	Locations []string        `json:"locations"`
}

// LicenseDetail contains detailed license information
type LicenseDetail struct {
	ID                    string   `json:"id"`
	Name                  string   `json:"name,omitempty"`
	IsDeprecatedLicenseID bool     `json:"isDeprecatedLicenseId"`
	IsOsiApproved         bool     `json:"isOsiApproved"`
	DetailsURL            string   `json:"detailsUrl"`
	Evidence              []string `json:"evidence,omitempty"`
}

// NewRunResponse creates a new RunResponse with default values
func NewRunResponse(argv []string, policy *Policy) *RunResponse {
	return &RunResponse{
		Tool:    internal.ApplicationName,
		Version: internal.ApplicationVersion,
		Run: RunDetails{
			Argv: argv,
			Policy: PolicyConfig{
				Rules: PolicyRules{
					Allow:          policy.Allow,
					IgnorePackages: policy.IgnorePackages,
				},
				RequireLicense:      policy.RequireLicense,
				RequireKnownLicense: policy.RequireKnownLicense,
			},
			Targets: []TargetResult{},
		},
	}
}

// AddTarget adds a target result to the response
func (r *RunResponse) AddTarget(source SourceInfo, evaluation TargetEvaluation) {
	r.Run.Targets = append(r.Run.Targets, TargetResult{
		Source:     source,
		Evaluation: evaluation,
	})
}

// ConvertEvaluationToTarget converts an EvaluationResult to TargetEvaluation
func ConvertEvaluationToTarget(evalResult *EvaluationResult, policy *Policy) TargetEvaluation {
	// Calculate unique licenses
	uniqueLicenses := make(map[string]bool)
	allowedLicenses := make(map[string]bool)
	deniedLicenses := make(map[string]bool)
	unrecognizedLicenses := make(map[string]bool)

	// Count unlicensed packages
	unlicensedCount := 0

	// Process all packages to gather statistics
	for _, pkg := range evalResult.AllowedPackages {
		for _, license := range pkg.Package.Licenses {
			licenseStr := license.String()
			uniqueLicenses[licenseStr] = true
			allowedLicenses[licenseStr] = true
		}
		if len(pkg.Package.Licenses) == 0 {
			unlicensedCount++
		}
	}

	for _, pkg := range evalResult.DeniedPackages {
		if len(pkg.Package.Licenses) == 0 {
			unlicensedCount++
		} else {
			for _, license := range pkg.Package.Licenses {
				licenseStr := license.String()
				uniqueLicenses[licenseStr] = true
				deniedLicenses[licenseStr] = true

				// Track non-SPDX licenses separately for license summary
				if license.Name != "" && license.SPDXExpression == "" {
					unrecognizedLicenses[licenseStr] = true
				}
			}
		}
	}

	// Build findings with deduplication
	findings := EvaluationFindings{
		Packages: []PackageFinding{},
	}

	// Use a map to deduplicate packages by their unique identifier (name@version)
	packageMap := make(map[string]PackageFinding)

	// Add allowed packages
	for _, pkg := range evalResult.AllowedPackages {
		finding := packageToFinding(pkg.Package, "allow")
		key := pkg.Package.Name + "@" + pkg.Package.Version
		if _, exists := packageMap[key]; !exists {
			packageMap[key] = finding
		}
	}

	// Add denied packages with only their denied licenses
	for _, pkg := range evalResult.DeniedPackages {
		finding := packageToFindingWithDeniedLicenses(pkg.Package, "deny", pkg.DeniedLicenses)
		key := pkg.Package.Name + "@" + pkg.Package.Version
		if _, exists := packageMap[key]; !exists {
			packageMap[key] = finding
		}
	}

	// Add ignored packages
	for _, pkg := range evalResult.IgnoredPackages {
		finding := packageToFinding(pkg.Package, "ignore")
		key := pkg.Package.Name + "@" + pkg.Package.Version
		if _, exists := packageMap[key]; !exists {
			packageMap[key] = finding
		}
	}

	// Convert map back to slice
	for _, finding := range packageMap {
		findings.Packages = append(findings.Packages, finding)
	}

	// Determine compliance status
	status := "compliant"
	if len(evalResult.DeniedPackages) > 0 {
		status = "noncompliant"
	}

	return TargetEvaluation{
		Status: status,
		Summary: EvaluationSummaryJSON{
			Packages: PackageSummary{
				Total:      evalResult.Summary.TotalPackages,
				Allowed:    evalResult.Summary.AllowedPackages,
				Denied:     evalResult.Summary.DeniedPackages,
				Ignored:    evalResult.Summary.IgnoredPackages,
				Unlicensed: unlicensedCount,
			},
			Licenses: LicenseSummary{
				Unique:  len(uniqueLicenses),
				Allowed: len(allowedLicenses),
				Denied:  len(deniedLicenses),
				NonSPDX: len(unrecognizedLicenses),
			},
		},
		Findings: findings,
	}
}

// packageToFinding converts a Package to a PackageFinding
func packageToFinding(pkg Package, decision string) PackageFinding {
	licenseDetails := []LicenseDetail{}
	for _, license := range pkg.Licenses {
		detail := LicenseDetail{
			ID:                    license.String(),
			Name:                  license.Name,
			IsDeprecatedLicenseID: license.IsDeprecatedLicenseID,
			IsOsiApproved:         license.IsOsiApproved,
			DetailsURL:            license.DetailsURL,
			Evidence:              license.Locations,
		}
		if license.SPDXExpression != "" {
			detail.ID = license.SPDXExpression
			detail.Name = ""
		}
		licenseDetails = append(licenseDetails, detail)
	}

	// Generate package ID
	pkgID := pkg.Type + ":" + pkg.Name
	if pkg.Version != "" {
		pkgID += "@" + pkg.Version
	}

	return PackageFinding{
		ID:        pkgID,
		Name:      pkg.Name,
		Type:      pkg.Type,
		Version:   pkg.Version,
		Decision:  decision,
		Licenses:  licenseDetails,
		Locations: pkg.Locations,
	}
}

// packageToFindingWithDeniedLicenses converts a Package to a PackageFinding, filtering to only show denied licenses
func packageToFindingWithDeniedLicenses(pkg Package, decision string, deniedLicenses []License) PackageFinding {
	// Only include the licenses that were actually denied
	licenseDetails := []LicenseDetail{}

	if decision == "deny" && len(pkg.Licenses) == 0 {
		// Package denied due to no licenses
		licenseDetails = []LicenseDetail{} // Keep empty to indicate no licenses
	} else {
		// Find which licenses from the package are in the denied list
		for _, license := range pkg.Licenses {
			for _, denied := range deniedLicenses {
				if license.String() == denied.String() {
					detail := LicenseDetail{
						ID:                    license.String(),
						Name:                  license.Name,
						IsDeprecatedLicenseID: license.IsDeprecatedLicenseID,
						IsOsiApproved:         license.IsOsiApproved,
						DetailsURL:            license.DetailsURL,
						Evidence:              license.Locations,
					}
					if license.SPDXExpression != "" {
						detail.ID = license.SPDXExpression
						detail.Name = ""
					}
					licenseDetails = append(licenseDetails, detail)
					break
				}
			}
		}
	}

	// Generate package ID
	pkgID := pkg.Type + ":" + pkg.Name
	if pkg.Version != "" {
		pkgID += "@" + pkg.Version
	}

	return PackageFinding{
		ID:        pkgID,
		Name:      pkg.Name,
		Type:      pkg.Type,
		Version:   pkg.Version,
		Decision:  decision,
		Licenses:  licenseDetails,
		Locations: pkg.Locations,
	}
}

// DetermineSourceType determines the source type from user input
func DetermineSourceType(userInput string) string {
	if isStdin(userInput) {
		return "sbom"
	}
	if isFile(userInput) {
		if isArchive(userInput) {
			return "file"
		}
		// Could be SBOM or license file
		return "file"
	}
	if isDirectory(userInput) {
		return "dir"
	}
	// Assume container image
	return "image"
}
