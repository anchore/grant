package grant

import "testing"

// makePkg is a small helper for building a Package with a single named license.
func makePkg(name, version, licenseID string) Package {
	p := Package{Name: name, Version: version, Type: "python"}
	if licenseID != "" {
		p.Licenses = []License{{SPDXExpression: licenseID}}
	}
	return p
}

// TestBuildEvaluationFindingsDedupKeepsDenied guards the consistency contract
// between the rendered findings and the summary/exit-code path. An SBOM can
// catalog the same package twice (one entry with a license, one without), which
// lands the package in both AllowedPackages and DeniedPackages. The findings list
// must keep the denial so the table is not empty while the summary still reports a
// denial and the command exits non-zero (issue #454).
func TestBuildEvaluationFindingsDedupKeepsDenied(t *testing.T) {
	deniedLicense := License{SPDXExpression: "BSD"}

	evalResult := &EvaluationResult{
		// The license-less duplicate is allowed because RequireLicense is false.
		AllowedPackages: []PackageResult{
			{Package: makePkg("nodeenv", "1.10.0", ""), Reason: "package allowed - no license requirement"},
		},
		// The license-bearing entry is denied because BSD is not in the allow-list.
		DeniedPackages: []PackageResult{
			{
				Package:        makePkg("nodeenv", "1.10.0", "BSD"),
				DeniedLicenses: []License{deniedLicense},
				Reason:         "package denied due to 1 denied licenses",
			},
		},
		Summary: EvaluationSummary{
			TotalPackages:   1,
			AllowedPackages: 1,
			DeniedPackages:  1,
		},
	}

	findings := buildEvaluationFindings(evalResult)

	if len(findings.Packages) != 1 {
		t.Fatalf("expected a single deduplicated finding, got %d", len(findings.Packages))
	}
	got := findings.Packages[0]
	if got.Decision != DecisionDeny {
		t.Errorf("colliding name@version should keep the denial, got decision %q", got.Decision)
	}
	if len(got.Licenses) != 1 || got.Licenses[0].ID != "BSD" {
		t.Errorf("denied finding should carry the denied license BSD, got %+v", got.Licenses)
	}
}

// TestConvertEvaluationToTargetSummaryMatchesFindings asserts the invariant that
// drove issue #454: the number of denied findings the presenter would render must
// equal the denied count in the summary, and a non-empty denied set must yield a
// noncompliant status (which the check command turns into a non-zero exit code).
func TestConvertEvaluationToTargetSummaryMatchesFindings(t *testing.T) {
	policy := &Policy{Allow: []string{"MIT"}, RequireLicense: false}

	evalResult := &EvaluationResult{
		AllowedPackages: []PackageResult{
			// allowed via the allow-list
			{Package: makePkg("acme", "1.0.0", "MIT"), Reason: "all licenses allowed"},
			// the license-less duplicates of the two denied packages below
			{Package: makePkg("distlib", "0.4.0", ""), Reason: "package allowed - no license requirement"},
			{Package: makePkg("filelock", "3.21.2", ""), Reason: "package allowed - no license requirement"},
		},
		DeniedPackages: []PackageResult{
			{Package: makePkg("distlib", "0.4.0", "PSF-2.0"), DeniedLicenses: []License{{SPDXExpression: "PSF-2.0"}}, Reason: "package denied due to 1 denied licenses"},
			{Package: makePkg("filelock", "3.21.2", "Unlicense"), DeniedLicenses: []License{{SPDXExpression: "Unlicense"}}, Reason: "package denied due to 1 denied licenses"},
		},
		Summary: EvaluationSummary{TotalPackages: 3, AllowedPackages: 1, DeniedPackages: 2},
	}

	target := ConvertEvaluationToTarget(evalResult, policy)

	deniedFindings := 0
	for _, f := range target.Findings.Packages {
		if f.Decision == DecisionDeny {
			deniedFindings++
		}
	}

	if deniedFindings != target.Summary.Packages.Denied {
		t.Errorf("denied findings (%d) must match summary denied count (%d); the presenter renders findings, the exit code follows the summary",
			deniedFindings, target.Summary.Packages.Denied)
	}
	if target.Summary.Packages.Denied > 0 && target.Status != StatusNonCompliant {
		t.Errorf("a non-empty denied set must be noncompliant, got status %q", target.Status)
	}
}

// TestBuildEvaluationFindingsAllAllowedStaysAllowed confirms the fix does not
// flip clean results: with no denials the finding stays allow and nothing is
// reported as denied (the "No denied packages found." path with exit 0).
func TestBuildEvaluationFindingsAllAllowedStaysAllowed(t *testing.T) {
	evalResult := &EvaluationResult{
		AllowedPackages: []PackageResult{
			{Package: makePkg("acme", "1.0.0", "MIT"), Reason: "all licenses allowed"},
		},
		Summary: EvaluationSummary{TotalPackages: 1, AllowedPackages: 1},
	}

	findings := buildEvaluationFindings(evalResult)
	if len(findings.Packages) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings.Packages))
	}
	if findings.Packages[0].Decision != DecisionAllow {
		t.Errorf("expected allow decision, got %q", findings.Packages[0].Decision)
	}
}
