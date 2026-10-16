package grant

import (
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
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

func TestConvertEvaluationToTarget_LicenseCountsFollowDecisions(t *testing.T) {
	sb := sbom.SBOM{Source: source.Description{Name: "test"}, Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()}}
	// allowed through MIT, so GPL-3.0-only is an unused alternative
	sb.Artifacts.Packages.Add(pkg.Package{Name: "or", Version: "1.0.0", Licenses: pkg.NewLicenseSet(spdx("MIT OR GPL-3.0-only"))})
	// denied for ISC only, the OR passed
	sb.Artifacts.Packages.Add(pkg.Package{Name: "and", Version: "1.0.0", Licenses: pkg.NewLicenseSet(spdx("(MIT OR Apache-2.0) AND ISC"))})

	policy := &Policy{Allow: []string{"MIT"}}
	evalResult, err := (&Case{SBOMS: []sbom.SBOM{sb}}).Evaluate(policy)
	require.NoError(t, err)

	target := ConvertEvaluationToTarget(evalResult, policy)
	assert.Equal(t, LicenseSummary{Unique: 4, Allowed: 1, Denied: 1}, target.Summary.Licenses)
}
