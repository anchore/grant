package grant

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	require.NoError(t, err)

	// The duplicate collapses to one denied package; nothing is double-counted.
	// Three entries were cataloged (acme + the two dup-pkg entries) but only two
	// unique packages are evaluated.
	wantSummary := EvaluationSummary{CatalogedPackages: 3, TotalPackages: 2, AllowedPackages: 1, DeniedPackages: 1, IgnoredPackages: 0}
	assert.Equal(t, wantSummary, evalResult.Summary)

	target := ConvertEvaluationToTarget(evalResult, policy)

	assert.Equal(t, 3, target.Summary.Packages.Cataloged, "cataloged should report the pre-merge package count")
	assert.Equal(t, 2, target.Summary.Packages.Total, "total should report the merged, unique package count")
	assert.Zero(t, target.Summary.Packages.Unlicensed, "the license-less duplicate is not a separate unlicensed package")

	deniedFindings := 0
	deniedNames := make(map[string]bool)
	for _, f := range target.Findings.Packages {
		if f.Decision == DecisionDeny {
			deniedFindings++
			deniedNames[f.Name] = true
		}
	}

	assert.Equal(t, target.Summary.Packages.Denied, deniedFindings,
		"denied findings must match the summary denied count; the presenter renders findings, the exit code follows the summary")
	assert.True(t, deniedNames["dup-pkg"], "dup-pkg must appear as a denied finding")
	assert.Equal(t, StatusNonCompliant, target.Status, "a non-empty denied set must be noncompliant")
}

func TestBuildEvaluationFindingsAllAllowedStaysAllowed(t *testing.T) {
	evalResult := &EvaluationResult{
		AllowedPackages: []PackageResult{
			{Package: makePkg("acme", "1.0.0", "MIT"), Reason: "all licenses allowed"},
		},
		Summary: EvaluationSummary{TotalPackages: 1, AllowedPackages: 1},
	}

	findings := buildEvaluationFindings(evalResult)
	require.Len(t, findings.Packages, 1)
	assert.Equal(t, DecisionAllow, findings.Packages[0].Decision)
}
