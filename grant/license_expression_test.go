package grant

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// these tests pin the SPDX behavior documented in license_expression.go and on licenseMatcher. They
// go through grant's own entry points, so a different SPDX implementation underneath should fail
// here wherever it disagrees.

// renderTerm renders a term tree the way the tests expect it, showing a leaf's atom when it differs
// from the license it flattened into
func renderTerm(t licenseTerm) string {
	if t.op == "" {
		if t.atom != "" && t.atom != t.member {
			return t.member + "[" + t.atom + "]"
		}
		return t.member
	}
	parts := make([]string, 0, len(t.terms))
	for _, term := range t.terms {
		parts = append(parts, renderTerm(term))
	}
	return t.op + "(" + strings.Join(parts, ", ") + ")"
}

func TestConvertSyftLicenses_ExpressionTree(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		// wantTree is the rendered tree, or empty when the declaration must fall back to one
		// non-SPDX license under the declared value (the strict reading)
		wantTree     string
		wantLicenses []string
	}{
		{name: "OR", expression: "MIT OR Apache-2.0", wantTree: "OR(MIT, Apache-2.0)", wantLicenses: []string{"MIT", "Apache-2.0"}},
		{name: "AND binds tighter than OR (left)", expression: "MIT OR GPL-3.0-only AND Apache-2.0", wantTree: "OR(MIT, AND(GPL-3.0-only, Apache-2.0))"},
		{name: "AND binds tighter than OR (right)", expression: "GPL-3.0-only AND Apache-2.0 OR MIT", wantTree: "OR(AND(GPL-3.0-only, Apache-2.0), MIT)"},
		{name: "WITH binds tighter than AND", expression: "MIT AND Apache-2.0 WITH LLVM-exception", wantTree: "AND(MIT, Apache-2.0 WITH LLVM-exception)"},
		{name: "WITH inside an OR chain", expression: "MIT OR GPL-2.0-only WITH Classpath-exception-2.0 AND Apache-2.0", wantTree: "OR(MIT, AND(GPL-2.0-only WITH Classpath-exception-2.0, Apache-2.0))"},
		{name: "parentheses override precedence", expression: "(MIT OR BSD-3-Clause) AND GPL-3.0-only", wantTree: "AND(OR(MIT, BSD-3-Clause), GPL-3.0-only)"},
		{name: "redundant parentheses", expression: "((MIT))", wantTree: "MIT"},
		{name: "spaces inside parentheses", expression: "( MIT )", wantTree: "MIT"},
		{name: "parenthesis touching an operator", expression: "MIT OR(Apache-2.0)", wantTree: "OR(MIT, Apache-2.0)"},
		{name: "parentheses touching on both sides", expression: "(MIT)OR(Apache-2.0)", wantTree: "OR(MIT, Apache-2.0)"},
		{name: "repeated spaces", expression: "MIT  OR Apache-2.0", wantTree: "OR(MIT, Apache-2.0)"},
		{name: "license ids are normalized", expression: "mit OR apache-2.0", wantTree: "OR(MIT, Apache-2.0)"},
		{name: "exceptions are normalized", expression: "Apache-2.0 WITH llvm-exception", wantTree: "Apache-2.0 WITH LLVM-exception", wantLicenses: []string{"Apache-2.0 WITH LLVM-exception"}},
		{name: "plus normalizes to or-later", expression: "GPL-2.0+", wantTree: "GPL-2.0-or-later", wantLicenses: []string{"GPL-2.0-or-later"}},
		{name: "plus is kept when there is no or-later form", expression: "Apache-2.0+", wantTree: "Apache-2.0[Apache-2.0+]", wantLicenses: []string{"Apache-2.0"}},
		{name: "plus on an or-later id is absorbed", expression: "GPL-2.0-or-later+", wantTree: "GPL-2.0-or-later"},
		{name: "plus with an exception", expression: "GPL-2.0+ WITH Classpath-exception-2.0", wantTree: "GPL-2.0-or-later WITH Classpath-exception-2.0"},
		{name: "spaced DocumentRef is normalized", expression: "DocumentRef-a : LicenseRef-b", wantTree: "DocumentRef-a:LicenseRef-b"},
		{name: "duplicate atoms flatten once", expression: "MIT OR MIT", wantTree: "OR(MIT, MIT)", wantLicenses: []string{"MIT"}},
		{name: "unknown atoms keep their own text", expression: "Apache-2.0 OR LicenseRef-z", wantTree: "OR(Apache-2.0, LicenseRef-z)", wantLicenses: []string{"Apache-2.0", "LicenseRef-z"}},

		// each of these is rejected by go-spdx and must stay strict
		{name: "lowercase AND is an error", expression: "MIT and Apache-2.0"},
		{name: "lowercase OR is an error", expression: "MIT or Apache-2.0"},
		{name: "lowercase WITH is an error", expression: "MIT with LLVM-exception"},
		{name: "tab is an error", expression: "MIT\tOR Apache-2.0"},
		{name: "newline is an error", expression: "MIT\nOR Apache-2.0"},
		{name: "space before plus is an error", expression: "GPL-2.0 +"},
		{name: "plus on a LicenseRef is an error", expression: "LicenseRef-x+"},
		{name: "WITH on a LicenseRef is an error", expression: "LicenseRef-x WITH LLVM-exception"},
		{name: "parenthesis touching an id is an error", expression: "MIT(Apache-2.0)"},
		{name: "WITH after a group is an error", expression: "(MIT OR Apache-2.0) WITH LLVM-exception"},
		{name: "license used as an exception is an error", expression: "Apache-2.0 WITH MIT"},
		{name: "dangling operator is an error", expression: "MIT AND"},
		{name: "dangling parenthesis (go-spdx panics) is an error", expression: "MIT AND ("},
		{name: "NOASSERTION is an error", expression: "NOASSERTION"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			licenses, declared := convertSyftLicenses(pkg.NewLicenseSet(pkg.License{Value: tt.expression, SPDXExpression: tt.expression}))
			require.Len(t, declared, 1)

			var got []string
			for _, l := range licenses {
				got = append(got, l.String())
			}

			if tt.wantTree == "" {
				assert.Equal(t, []string{tt.expression}, got, "a rejected expression is kept whole")
				assert.False(t, licenses[0].IsSPDX())
				assert.Equal(t, tt.expression, renderTerm(declared[0]))
				return
			}

			assert.Equal(t, tt.wantTree, renderTerm(declared[0]))
			if tt.wantLicenses != nil {
				assert.ElementsMatch(t, tt.wantLicenses, got)
			}
			// every leaf must refer to a license that was actually added
			declared[0].leaves(func(leaf licenseTerm) {
				assert.Contains(t, got, leaf.member)
			})
		})
	}
}

func TestParseLicenseExpression_RejectsIncompleteInput(t *testing.T) {
	// go-spdx rejects these first, the parser must not quietly accept them either
	for _, expression := range []string{"MIT OR", "(MIT", "MIT)", "AND MIT", "MIT WITH", "DocumentRef-a:"} {
		_, err := parseLicenseExpression(expression)
		assert.Error(t, err, expression)
	}
}

// evaluateSyftLicenses evaluates one package carrying the given syft license entries
func evaluateSyftLicenses(t *testing.T, policy *Policy, licenses ...pkg.License) PackageResult {
	t.Helper()
	sb := sbom.SBOM{Source: source.Description{Name: "test"}, Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()}}
	sb.Artifacts.Packages.Add(pkg.Package{Name: "pkg", Version: "1.0.0", Licenses: pkg.NewLicenseSet(licenses...)})
	result, err := (&Case{SBOMS: []sbom.SBOM{sb}}).Evaluate(policy)
	require.NoError(t, err)
	require.Equal(t, 1, result.Summary.TotalPackages)
	if len(result.AllowedPackages) == 1 {
		return result.AllowedPackages[0]
	}
	require.Len(t, result.DeniedPackages, 1)
	return result.DeniedPackages[0]
}

func spdx(expression string) pkg.License {
	return pkg.License{Value: expression, SPDXExpression: expression}
}

func TestLicenseMatcher_Ranges(t *testing.T) {
	tests := []struct {
		name     string
		declared string
		allow    []string
		want     bool
	}{
		// declared side ranges (SPDX 2.3 Annex D.3)
		{name: "or-later allowed by a later only", declared: "GPL-2.0-or-later", allow: []string{"GPL-3.0-only"}, want: true},
		{name: "plus allowed by a later only", declared: "GPL-2.0+", allow: []string{"GPL-3.0-only"}, want: true},
		{name: "plus without an or-later form", declared: "Apache-1.0+", allow: []string{"Apache-2.0"}, want: true},
		{name: "plus on MPL", declared: "MPL-1.1+", allow: []string{"MPL-2.0"}, want: true},
		{name: "plus on LGPL", declared: "LGPL-2.1+", allow: []string{"LGPL-3.0-only"}, want: true},
		{name: "range covers its base version", declared: "GPL-2.0-or-later", allow: []string{"GPL-2.0-only"}, want: true},
		{name: "only is exact upward", declared: "GPL-2.0-only", allow: []string{"GPL-3.0-only"}},
		{name: "only is exact downward", declared: "GPL-3.0-only", allow: []string{"GPL-2.0-only"}},
		{name: "range stays in its family (LGPL vs GPL)", declared: "LGPL-2.0-or-later", allow: []string{"GPL-3.0-only"}},
		{name: "AGPL is not GPL", declared: "AGPL-3.0-only", allow: []string{"GPL-3.0-only"}},

		// deprecated ids
		{name: "deprecated id allowed by its only form", declared: "GPL-2.0", allow: []string{"GPL-2.0-only"}, want: true},
		{name: "only form allowed by the deprecated id", declared: "GPL-2.0-only", allow: []string{"GPL-2.0"}, want: true},
		{name: "deprecated id is not a range", declared: "GPL-2.0", allow: []string{"GPL-3.0-only"}},

		// exceptions
		{name: "WITH is not allowed by the bare license", declared: "Apache-2.0 WITH LLVM-exception", allow: []string{"Apache-2.0"}},
		{name: "WITH is allowed by the same WITH", declared: "Apache-2.0 WITH LLVM-exception", allow: []string{"Apache-2.0 WITH LLVM-exception"}, want: true},
		{name: "WITH on a range is not allowed by a later bare license", declared: "GPL-2.0-or-later WITH Classpath-exception-2.0", allow: []string{"GPL-3.0-only"}},

		// the allow list is never widened
		{name: "or-later allow entry is literal", declared: "GPL-3.0-only", allow: []string{"GPL-2.0-or-later"}},
		{name: "plus allow entry is literal", declared: "GPL-3.0-only", allow: []string{"GPL-2.0+"}},
		{name: "or-later allow entry does not cover a later range", declared: "GPL-3.0-or-later", allow: []string{"GPL-2.0-or-later"}},
		{name: "or-later allow entry matches itself", declared: "GPL-2.0-or-later", allow: []string{"GPL-2.0-or-later"}, want: true},
		{name: "or-later allow entry with an exception is literal", declared: "GPL-3.0-only WITH Classpath-exception-2.0", allow: []string{"GPL-2.0-or-later WITH Classpath-exception-2.0"}},
		{name: "plus allow entry with an exception is literal", declared: "Apache-2.0 WITH LLVM-exception", allow: []string{"Apache-1.0+ WITH LLVM-exception"}},
		{name: "or-later allow entry with an exception matches itself", declared: "GPL-2.0-or-later WITH Classpath-exception-2.0", allow: []string{"GPL-2.0-or-later WITH Classpath-exception-2.0"}, want: true},
		{name: "allow entries are case sensitive", declared: "MIT", allow: []string{"mit"}},
		{name: "allow entries are case sensitive for ranges", declared: "GPL-2.0-or-later", allow: []string{"gpl-3.0-only"}},

		// allow entries go-spdx cannot parse must not disable ranges for the rest
		{name: "glob next to a range target", declared: "GPL-2.0-or-later", allow: []string{"BSD-*", "GPL-3.0-only"}, want: true},
		{name: "unknown id next to a range target", declared: "GPL-2.0-or-later", allow: []string{"Not-A-License-1.0", "GPL-3.0-only"}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluateSyftLicenses(t, &Policy{Allow: tt.allow}, spdx(tt.declared))
			assert.Equal(t, tt.want, len(result.DeniedLicenses) == 0, "denied: %v", result.DeniedLicenses)
		})
	}
}

// TestEvaluate_SatisfiesUnsoundness pins cases go-spdx v2.7.0 Satisfies gets wrong on whole
// expressions, which is why grant evaluates the operators itself
func TestEvaluate_SatisfiesUnsoundness(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		policy     *Policy
		wantDenied []string
	}{
		{
			// Satisfies drops an OR made only of LicenseRefs when it sits under an AND
			name:       "LicenseRef-only OR under AND",
			expression: "MIT AND (LicenseRef-a OR LicenseRef-b)",
			policy:     &Policy{Allow: []string{"MIT"}},
			wantDenied: []string{"LicenseRef-a", "LicenseRef-b"},
		},
		{
			name:       "LicenseRef-only OR under AND with require-known-license",
			expression: "MIT AND (LicenseRef-a OR LicenseRef-b)",
			policy:     &Policy{Allow: []string{"MIT"}, RequireKnownLicense: true},
			wantDenied: []string{"LicenseRef-a", "LicenseRef-b"},
		},
		{
			// Satisfies aliases slices while expanding nested ANDs and loses SSPL-1.0
			name:       "required license lost in nested AND",
			expression: "((((Apache-2.0 AND ISC) AND (SSPL-1.0 AND 0BSD)) AND GPL-3.0-only) AND (GPL-3.0-only OR (MIT AND MIT)))",
			policy:     &Policy{Allow: []string{"MIT", "Apache-2.0", "GPL-3.0-only", "ISC", "0BSD"}},
			wantDenied: []string{"SSPL-1.0"},
		},
		{
			// Satisfies is false for an allowed LicenseRef inside an OR
			name:       "allowed LicenseRef alternative",
			expression: "LicenseRef-x OR GPL-3.0-only",
			policy:     &Policy{Allow: []string{"LicenseRef-x"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluateSyftLicenses(t, tt.policy, spdx(tt.expression))
			var denied []string
			for _, l := range result.DeniedLicenses {
				denied = append(denied, l.String())
			}
			assert.ElementsMatch(t, tt.wantDenied, denied)
		})
	}
}

func TestEvaluate_NestedExpressionIsLinear(t *testing.T) {
	// Satisfies expands AND-of-ORs into every combination: 20 of these took ~19s, 40 would not finish
	expression := "GPL-3.0-only"
	for range 40 {
		expression = "(MIT OR ISC) AND " + expression
	}

	sb := sbom.SBOM{Source: source.Description{Name: "test"}, Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()}}
	sb.Artifacts.Packages.Add(pkg.Package{Name: "pkg", Version: "1.0.0", Licenses: pkg.NewLicenseSet(spdx(expression))})

	done := make(chan *EvaluationResult, 1)
	go func() {
		result, _ := (&Case{SBOMS: []sbom.SBOM{sb}}).Evaluate(&Policy{Allow: []string{"MIT"}})
		done <- result
	}()
	select {
	case result := <-done:
		require.Len(t, result.DeniedPackages, 1)
		// every (MIT OR ISC) passed, so only the license that failed the AND is denied
		assert.Equal(t, []string{"GPL-3.0-only"}, licenseStrings(result.DeniedPackages[0].DeniedLicenses))
	case <-time.After(10 * time.Second):
		t.Fatal("evaluation did not finish, expression evaluation is not linear")
	}
}

func TestEvaluate_DeclarationsAreTrackedByTheLicenseTheyAdd(t *testing.T) {
	tests := []struct {
		name       string
		licenses   []pkg.License
		policy     *Policy
		wantDenied []string
	}{
		{
			// the standalone declaration repeats an unknown atom of the OR, and must still be judged
			name:       "standalone repeat of an OR alternative",
			licenses:   []pkg.License{spdx("Apache-2.0 OR LicenseRef-z"), spdx("LicenseRef-z")},
			policy:     &Policy{Allow: []string{"Apache-2.0"}},
			wantDenied: []string{"LicenseRef-z"},
		},
		{
			name:       "non-SPDX declaration named like an OR alternative",
			licenses:   []pkg.License{spdx("MIT OR GPL-3.0-only"), {Value: "GPL-3.0-only"}},
			policy:     &Policy{Allow: []string{"MIT"}},
			wantDenied: []string{"GPL-3.0-only"},
		},
		{
			// Value and SPDXExpression are separate fields in an SBOM, Value must not decide what an
			// atom refers to
			name:       "Value spoofing an allowed license",
			licenses:   []pkg.License{{Value: "MIT", SPDXExpression: "MIT AND LicenseRef-evil"}},
			policy:     &Policy{Allow: []string{"MIT"}, RequireKnownLicense: true},
			wantDenied: []string{"LicenseRef-evil"},
		},
		{
			name:     "differently spelled duplicates of one expression",
			licenses: []pkg.License{spdx("mit OR LicenseRef-x"), spdx("MIT OR LicenseRef-x")},
			policy:   &Policy{Allow: []string{"MIT"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluateSyftLicenses(t, tt.policy, tt.licenses...)
			var denied []string
			for _, l := range result.DeniedLicenses {
				denied = append(denied, l.String())
			}
			assert.ElementsMatch(t, tt.wantDenied, denied)
		})
	}
}

func TestEvaluate_RangeOnlyLeafIsReportedAllowed(t *testing.T) {
	// "MPL-1.1+" flattens to "MPL-1.1", which only passes through the leaf's range
	result := evaluateSyftLicenses(t, &Policy{Allow: []string{"MPL-2.0"}}, spdx("MPL-1.1+"))
	assert.Empty(t, result.DeniedLicenses)
	require.Len(t, result.AllowedLicenses, 1)
	assert.Equal(t, "MPL-1.1", result.AllowedLicenses[0].String())
	assert.Equal(t, "all licenses allowed", result.Reason)
}

func TestLicenseMatcher_RangeAllowEntryWithExceptionUnderRequireKnown(t *testing.T) {
	// WITH leaves are known since #555, so require-known-license no longer hides an allow-side range
	policy := &Policy{Allow: []string{"GPL-2.0-or-later WITH Classpath-exception-2.0"}, RequireKnownLicense: true}
	result := evaluateSyftLicenses(t, policy, spdx("GPL-3.0-only WITH Classpath-exception-2.0"))
	assert.NotEmpty(t, result.DeniedLicenses)
}

func TestMergeDuplicatePackages_EachPackageOnce(t *testing.T) {
	// a package is filed under each of its licenses, which must not repeat its declarations
	p, terms := convertSyftPackage(pkg.Package{Name: "pkg", Version: "1.0.0", Licenses: pkg.NewLicenseSet(spdx("MIT OR Apache-2.0 OR ISC"))})
	byLicense := map[string][]*Package{"MIT": {p}, "Apache-2.0": {p}, "ISC": {p}}

	merged, declared := mergeDuplicatePackages(byLicense, nil, declarations{p: terms})
	require.Len(t, merged, 1)
	assert.Len(t, declared[merged[0]], 1)
	assert.Len(t, merged[0].Licenses, 3)
}

func TestEvaluate_FailedDeclarationDeniesWithoutDeniedLicenses(t *testing.T) {
	// not reachable through ConvertSyftPackage: a failing leaf whose license is missing from the
	// package. The failed declaration alone must still deny.
	p := &Package{
		Name: "pkg", Version: "1.0.0",
		Licenses: []License{{SPDXExpression: "MIT"}},
	}
	declared := []licenseTerm{{member: "GPL-3.0-only", spdx: true, atom: "GPL-3.0-only"}}
	policy := &Policy{Allow: []string{"MIT"}}
	c := &Case{}
	packageResult := c.evaluatePackage(p, declared, policy, newLicenseMatcher(policy))
	assert.Empty(t, packageResult.DeniedLicenses)

	result := &EvaluationResult{}
	c.categorizePackageResult(&packageResult, result)
	assert.Len(t, result.DeniedPackages, 1)
	assert.Empty(t, result.AllowedPackages)
}

func TestEvaluate_MalformedExpressionIsNamedByItself(t *testing.T) {
	// value and spdxExpression are independent SBOM fields. When the expression does not parse, it is
	// kept as one license named by the expression, so a value that disagrees cannot stand in for it.
	policy := &Policy{Allow: []string{"MIT"}}
	for _, value := range []string{"MIT", "sha256:0000"} {
		t.Run(value, func(t *testing.T) {
			result := evaluateSyftLicenses(t, policy, pkg.License{Value: value, SPDXExpression: "GPL-3.0-only AND ("})
			assert.Equal(t, []string{"GPL-3.0-only AND ("}, licenseStrings(result.DeniedLicenses))
		})
	}
}
