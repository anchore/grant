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

func TestConvertEvaluationToTarget(t *testing.T) {
	policy := &Policy{Allow: []string{"MIT"}, RequireLicense: false}

	c := createCaseFromPackages([]Package{
		makePkg("acme", "1.0.0", "MIT"),
		makePkg("dup-pkg", "1.0.0", "BSD-3-Clause"),
		makePkg("dup-pkg", "1.0.0", ""),
	})

	evalResult, err := c.Evaluate(policy)
	if err != nil {
		t.Fatalf("Evaluate() unexpected error: %v", err)
	}

	// The duplicate collapses to one denied package; nothing is double-counted.
	wantSummary := EvaluationSummary{TotalPackages: 2, AllowedPackages: 1, DeniedPackages: 1, IgnoredPackages: 0}
	if evalResult.Summary != wantSummary {
		t.Errorf("summary = %+v, want %+v", evalResult.Summary, wantSummary)
	}

	target := ConvertEvaluationToTarget(evalResult, policy)

	if target.Summary.Packages.Unlicensed != 0 {
		t.Errorf("unlicensed count = %d, want 0 (the license-less duplicate is not a separate package)", target.Summary.Packages.Unlicensed)
	}

	deniedFindings := 0
	deniedNames := make(map[string]bool)
	for _, f := range target.Findings.Packages {
		if f.Decision == DecisionDeny {
			deniedFindings++
			deniedNames[f.Name] = true
		}
	}

	if deniedFindings != target.Summary.Packages.Denied {
		t.Errorf("denied findings (%d) must match summary denied count (%d); the presenter renders findings, the exit code follows the summary",
			deniedFindings, target.Summary.Packages.Denied)
	}
	if !deniedNames["dup-pkg"] {
		t.Errorf("dup-pkg must appear as a denied finding, got findings %+v", target.Findings.Packages)
	}
	if target.Status != StatusNonCompliant {
		t.Errorf("a non-empty denied set must be noncompliant, got status %q", target.Status)
	}
}

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
