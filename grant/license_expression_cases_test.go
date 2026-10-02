package grant

import (
	"fmt"
	"math/rand/v2"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// these tests widen the coverage of license_expression_test.go. They are grounded in:
//
//   - SPDX 2.3 Annex D (https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions/): OR is a
//     choice (D.4.2), AND requires all (D.4.3), WITH attaches one exception to one license (D.4.4),
//     precedence is + > WITH > AND > OR (D.4.5), "+" means that version or any later one (D.3),
//     operators are case sensitive, ids are not
//   - SPDX 3.0.1 (https://spdx.github.io/spdx-spec/v3.0.1/annexes/spdx-license-expressions/), which
//     adds AdditionRef- after WITH and also allows all-lowercase operators
//   - go-spdx v2.7.0 spdxexp (scan.go, parse.go, spdxlicenses/license_ranges.go), which grant uses to
//     validate and normalize, and whose deviations from the spec are pinned below
//   - real expressions from crates.io, npm, Maven Central and PyPI
//
// expectations that the spec and grant's documented choices (see license_expression.go and
// licenseMatcher) call for but the implementation does not meet yet are kept as t.Skip("known gap: ...") cases so they are easy to find and flip on.

// licenseStrings returns the String() of every license
func licenseStrings(licenses []License) []string {
	out := make([]string, 0, len(licenses))
	for _, l := range licenses {
		out = append(out, l.String())
	}
	return out
}

// renderAtoms renders a raw parse tree by its leaf atoms (members are unset before conversion)
func renderAtoms(t licenseTerm) string {
	if t.op == "" {
		return t.atom
	}
	parts := make([]string, 0, len(t.terms))
	for _, term := range t.terms {
		parts = append(parts, renderAtoms(term))
	}
	return t.op + "(" + strings.Join(parts, ", ") + ")"
}

// evaluateEntries evaluates one SBOM per inner slice, each entry being one cataloged package. All
// entries share a name and version, so they merge into a single package.
func evaluateEntries(t *testing.T, policy *Policy, sboms ...[][]pkg.License) *EvaluationResult {
	t.Helper()
	c := &Case{}
	for _, entries := range sboms {
		sb := sbom.SBOM{Source: source.Description{Name: "test"}, Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()}}
		for _, licenses := range entries {
			sb.Artifacts.Packages.Add(pkg.Package{Name: "pkg", Version: "1.0.0", Licenses: pkg.NewLicenseSet(licenses...)})
		}
		c.SBOMS = append(c.SBOMS, sb)
	}
	result, err := c.Evaluate(policy)
	require.NoError(t, err)
	return result
}

func TestParseLicenseExpression_Grammar(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		want       string
	}{
		// a single leaf in every shape the leaf grammar allows
		{name: "bare id", expression: "MIT", want: "MIT"},
		{name: "id with plus", expression: "GPL-2.0+", want: "GPL-2.0+"},
		{name: "LicenseRef", expression: "LicenseRef-foo", want: "LicenseRef-foo"},
		{name: "LicenseRef with dots", expression: "LicenseRef-a.b.c", want: "LicenseRef-a.b.c"},
		{name: "LicenseRef named like an operator", expression: "LicenseRef-AND OR LicenseRef-OR", want: "OR(LicenseRef-AND, LicenseRef-OR)"},
		{name: "DocumentRef", expression: "DocumentRef-spdx-tool-1.2:LicenseRef-MIT-Style-2", want: "DocumentRef-spdx-tool-1.2:LicenseRef-MIT-Style-2"},
		{name: "spaced DocumentRef", expression: "DocumentRef-a : LicenseRef-b", want: "DocumentRef-a:LicenseRef-b"},
		{name: "DocumentRef named like an operator", expression: "DocumentRef-WITH:LicenseRef-AND", want: "DocumentRef-WITH:LicenseRef-AND"},
		{name: "DocumentRef with WITH stays one leaf", expression: "DocumentRef-a:LicenseRef-b WITH LLVM-exception", want: "DocumentRef-a:LicenseRef-b WITH LLVM-exception"},
		{name: "WITH", expression: "Apache-2.0 WITH LLVM-exception", want: "Apache-2.0 WITH LLVM-exception"},
		{name: "WITH after plus", expression: "GPL-2.0+ WITH Classpath-exception-2.0", want: "GPL-2.0+ WITH Classpath-exception-2.0"},

		// precedence (D.4.5): WITH > AND > OR, operators are n-ary
		{name: "long OR chain is one node", expression: "A OR B OR C OR D OR E OR F", want: "OR(A, B, C, D, E, F)"},
		{name: "long AND chain is one node", expression: "A AND B AND C AND D", want: "AND(A, B, C, D)"},
		{name: "AND groups in the middle of an OR chain", expression: "A OR B AND C OR D", want: "OR(A, AND(B, C), D)"},
		{name: "two AND groups under OR", expression: "A AND B OR C AND D", want: "OR(AND(A, B), AND(C, D))"},
		{name: "WITH binds inside AND inside OR", expression: "A OR B WITH E AND C", want: "OR(A, AND(B WITH E, C))"},
		{name: "WITH on both sides of AND", expression: "A WITH E AND B WITH F", want: "AND(A WITH E, B WITH F)"},

		// parentheses
		{name: "parentheses override precedence", expression: "(A OR B) AND C", want: "AND(OR(A, B), C)"},
		{name: "parentheses on the right", expression: "A AND (B OR C)", want: "AND(A, OR(B, C))"},
		{name: "parenthesized group keeps its own node", expression: "(A OR B) OR C", want: "OR(OR(A, B), C)"},
		{name: "redundant parentheses around an operator", expression: "((A AND B))", want: "AND(A, B)"},
		{name: "redundant parentheses around every leaf", expression: "(A) OR (B) AND (C)", want: "OR(A, AND(B, C))"},
		{name: "redundant parentheses around a WITH leaf", expression: "(A WITH E) OR B", want: "OR(A WITH E, B)"},
		{name: "adjacent groups", expression: "(A OR B)AND(C OR D)", want: "AND(OR(A, B), OR(C, D))"},
		{name: "deep nesting", expression: "((((((A))))))", want: "A"},
		{name: "deep alternating nesting", expression: "A AND (B OR (C AND (D OR (E AND F))))", want: "AND(A, OR(B, AND(C, OR(D, AND(E, F)))))"},
		{name: "spaces inside parentheses", expression: "(  A  OR  B  )", want: "OR(A, B)"},
		{name: "leading and trailing spaces", expression: "  A OR B  ", want: "OR(A, B)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			term, err := parseLicenseExpression(tt.expression)
			require.NoError(t, err)
			assert.Equal(t, tt.want, renderAtoms(term))
		})
	}
}

func TestParseLicenseExpression_RejectsMalformed(t *testing.T) {
	// the parser runs after go-spdx, but must not quietly accept a broken shape on its own
	for _, expression := range []string{
		"", "()", "(", ")", "A OR", "OR A", "A AND AND B", "A OR OR B", "A B", "(A OR B", "A OR B)",
		"((A)", "A WITH", "WITH E", "A WITH (E)", "A:", ":A", "DocumentRef-a:", "A AND ()",
	} {
		_, err := parseLicenseExpression(expression)
		assert.Error(t, err, "%q", expression)
	}
}

func TestParseLicenseExpression_VeryLongInput(t *testing.T) {
	// a long OR chain and a deeply nested expression both parse in one pass
	ids := make([]string, 500)
	for i := range ids {
		ids[i] = fmt.Sprintf("LicenseRef-%d", i)
	}
	term, err := parseLicenseExpression(strings.Join(ids, " OR "))
	require.NoError(t, err)
	assert.Equal(t, opOR, term.op)
	assert.Len(t, term.terms, 500)

	deep := strings.Repeat("(", maxExpressionDepth) + "MIT" + strings.Repeat(")", maxExpressionDepth)
	term, err = parseLicenseExpression(deep)
	require.NoError(t, err)
	assert.Equal(t, "MIT", renderAtoms(term))

	// deeper nesting is rejected before the recursion can exhaust the stack
	tooDeep := strings.Repeat("(", 1_000_000) + "MIT" + strings.Repeat(")", 1_000_000)
	_, err = parseLicenseExpression(tooDeep)
	assert.Error(t, err)
}

func TestConvertSyftLicenses_GoSPDXNormalization(t *testing.T) {
	// what go-spdx v2.7.0 accepts and how it normalizes each atom. A different SPDX implementation
	// that disagrees shows up here.
	tests := []struct {
		name       string
		expression string
		// wantTree is the rendered tree (see renderTerm), empty when the declaration is rejected and
		// kept whole as one non-SPDX license
		wantTree string
		// wantStrictAtoms is set when go-spdx accepts what grant cannot parse, so every atom is
		// required (in go-spdx's map order, so compared unordered)
		wantStrictAtoms []string
	}{
		// case: ids are case insensitive (D.2), operators are not
		{name: "mixed case id", expression: "Mit", wantTree: "MIT"},
		{name: "upper case id", expression: "APACHE-2.0", wantTree: "Apache-2.0"},
		{name: "lower case plus", expression: "gpl-2.0+", wantTree: "GPL-2.0-or-later"},
		{name: "mixed case operator is an error", expression: "MIT Or Apache-2.0"},
		{name: "lower case LicenseRef prefix is an error", expression: "licenseref-foo"},

		// deprecated ids are valid (Annex A.3) and keep their own id
		{name: "deprecated GPL-2.0", expression: "GPL-2.0", wantTree: "GPL-2.0"},
		{name: "deprecated GPL-3.0", expression: "GPL-3.0 OR MIT", wantTree: "OR(GPL-3.0, MIT)"},
		{name: "deprecated LGPL-2.1+ normalizes to or-later", expression: "LGPL-2.1+", wantTree: "LGPL-2.1-or-later"},
		{name: "deprecated GPL-1.0+ normalizes to or-later", expression: "GPL-1.0+", wantTree: "GPL-1.0-or-later"},
		{name: "deprecated id with a built in exception", expression: "GPL-2.0-with-classpath-exception OR MIT", wantTree: "OR(GPL-2.0-with-classpath-exception, MIT)"},
		{name: "deprecated eCos-2.0", expression: "eCos-2.0", wantTree: "eCos-2.0"},
		{name: "deprecated AGPL-3.0", expression: "AGPL-3.0", wantTree: "AGPL-3.0"},

		// go-spdx accepts suffixes the license list does not have
		{name: "only suffix on an id without one", expression: "MIT-only", wantTree: "MIT"},
		{name: "or-later on an id without one keeps a plus", expression: "Apache-2.0-or-later", wantTree: "Apache-2.0[Apache-2.0+]"},
		{name: "plus on a non versioned id", expression: "MIT+", wantTree: "MIT[MIT+]"},
		{name: "plus with an exception on an id without or-later", expression: "MIT+ WITH LLVM-exception", wantTree: "MIT+ WITH LLVM-exception"},

		// whitespace (only U+0020 separates tokens)
		{name: "leading and trailing spaces", expression: "  MIT OR GPL-3.0-only  ", wantTree: "OR(MIT, GPL-3.0-only)"},
		{name: "non breaking space is an error", expression: "MIT OR ISC"},
		{name: "CRLF is an error", expression: "MIT OR\r\nISC"},

		// operators must be separated by space or parentheses (D.4), go-spdx is laxer: it reads
		// operators by prefix. grant cannot split those, so it requires every atom (strict).
		{name: "operator glued to the next id under AND", expression: "MIT ANDApache-2.0", wantStrictAtoms: []string{"MIT", "Apache-2.0"}},
		{name: "operator glued to the next id under OR falls back to AND", expression: "MIT ORApache-2.0", wantStrictAtoms: []string{"MIT", "Apache-2.0"}},
		{name: "operators touching parentheses", expression: "(MIT)AND(Apache-2.0)", wantTree: "AND(MIT, Apache-2.0)"},

		// WITH
		{name: "WITH Classpath on an only id", expression: "GPL-2.0-only WITH Classpath-exception-2.0", wantTree: "GPL-2.0-only WITH Classpath-exception-2.0"},
		{name: "WITH on a deprecated id", expression: "GPL-2.0 WITH Classpath-exception-2.0", wantTree: "GPL-2.0 WITH Classpath-exception-2.0"},
		{name: "two WITHs on one license is an error", expression: "Apache-2.0 WITH LLVM-exception WITH LLVM-exception"},
		{name: "plus after an exception is an error", expression: "GPL-2.0-or-later WITH Classpath-exception-2.0+"},
		{name: "exception on its own is an error", expression: "Classpath-exception-2.0"},
		{name: "exception as an OR alternative is an error", expression: "LLVM-exception OR MIT"},
		{name: "AdditionRef (SPDX 3) is an error", expression: "Apache-2.0 WITH AdditionRef-foo"},
		{name: "DocumentRef with WITH is an error", expression: "DocumentRef-x:LicenseRef-y WITH LLVM-exception"},

		// references
		{name: "LicenseRef with dots", expression: "LicenseRef-a.b OR MIT", wantTree: "OR(LicenseRef-a.b, MIT)"},
		{name: "empty LicenseRef is an error", expression: "LicenseRef-"},
		{name: "DocumentRef without LicenseRef is an error", expression: "DocumentRef-a:MIT"},
		{name: "plus on a DocumentRef is an error", expression: "DocumentRef-x:LicenseRef-y+"},
		{name: "two LicenseRefs joined by a colon is an error", expression: "LicenseRef-a:LicenseRef-b"},

		// other shapes package managers produce
		{name: "comma separated list (npm legacy) is an error", expression: "MIT,ISC"},
		{name: "slash separated list (Cargo legacy) is an error", expression: "MIT/Apache-2.0"},
		{name: "space separated list is an error", expression: "MIT ISC"},
		{name: "NONE is an error", expression: "NONE"},
		{name: "NOASSERTION inside an expression is an error", expression: "MIT AND NOASSERTION"},
		{name: "unknown id is an error", expression: "Not-A-License-1.0 OR MIT"},
		{name: "empty parentheses are an error", expression: "MIT OR ()"},
		{name: "doubled operator is an error", expression: "MIT OR OR ISC"},
		{name: "unbalanced parentheses are an error", expression: "((MIT OR ISC)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			licenses, declared := convertSyftLicenses(pkg.NewLicenseSet(spdx(tt.expression)))
			require.Len(t, declared, 1)
			if tt.wantStrictAtoms != nil {
				assert.Equal(t, opAND, declared[0].op)
				var members []string
				declared[0].leaves(func(leaf licenseTerm) { members = append(members, leaf.member) })
				assert.ElementsMatch(t, tt.wantStrictAtoms, members)
				return
			}
			if tt.wantTree == "" {
				assert.Equal(t, []string{strings.TrimSpace(tt.expression)}, licenseStrings(licenses), "a rejected expression is kept whole")
				assert.False(t, licenses[0].IsSPDX())
				return
			}
			assert.Equal(t, tt.wantTree, renderTerm(declared[0]))
			declared[0].leaves(func(leaf licenseTerm) {
				assert.Contains(t, licenseStrings(licenses), leaf.member, "every leaf refers to a license that was added")
			})
		})
	}
}

func TestEvaluate_OperatorTruthTables(t *testing.T) {
	// every subset of {MIT, Apache-2.0, ISC} as the allow list, against two and three operand shapes.
	// For plain SPDX ids the result is fully determined by boolean logic over "is this leaf allowed",
	// and reporting follows from it: a passing package lists no denied licenses, a failing one lists
	// exactly the leaves that are not allowed, and allowed leaves are listed as allowed either way.
	ids := []string{"MIT", "Apache-2.0", "ISC"}
	shapes := []struct {
		expression string
		eval       func(a, b, c bool) bool
		leaves     []string
	}{
		{"MIT OR Apache-2.0", func(a, b, _ bool) bool { return a || b }, ids[:2]},
		{"MIT AND Apache-2.0", func(a, b, _ bool) bool { return a && b }, ids[:2]},
		{"MIT OR Apache-2.0 OR ISC", func(a, b, c bool) bool { return a || b || c }, ids},
		{"MIT AND Apache-2.0 AND ISC", func(a, b, c bool) bool { return a && b && c }, ids},
		{"MIT OR Apache-2.0 AND ISC", func(a, b, c bool) bool { return a || (b && c) }, ids},
		{"MIT AND Apache-2.0 OR ISC", func(a, b, c bool) bool { return (a && b) || c }, ids},
		{"(MIT OR Apache-2.0) AND ISC", func(a, b, c bool) bool { return (a || b) && c }, ids},
		{"MIT AND (Apache-2.0 OR ISC)", func(a, b, c bool) bool { return a && (b || c) }, ids},
		{"(MIT AND Apache-2.0) OR ISC", func(a, b, c bool) bool { return (a && b) || c }, ids},
		{"MIT OR (Apache-2.0 AND ISC)", func(a, b, c bool) bool { return a || (b && c) }, ids},
		{"((MIT)) OR ((Apache-2.0) AND (ISC))", func(a, b, c bool) bool { return a || (b && c) }, ids},
		{"ISC OR MIT AND Apache-2.0", func(a, b, c bool) bool { return c || (a && b) }, ids},
	}
	for _, shape := range shapes {
		for mask := range 8 {
			var allow []string
			allowed := map[string]bool{}
			for i, id := range ids {
				if mask&(1<<i) != 0 {
					allow = append(allow, id)
					allowed[id] = true
				}
			}
			t.Run(fmt.Sprintf("%s allow=%v", shape.expression, allow), func(t *testing.T) {
				result := evaluateSyftLicenses(t, &Policy{Allow: allow}, spdx(shape.expression))
				want := shape.eval(allowed["MIT"], allowed["Apache-2.0"], allowed["ISC"])

				var wantAllowed, notAllowed []string
				for _, leaf := range shape.leaves {
					if allowed[leaf] {
						wantAllowed = append(wantAllowed, leaf)
					} else {
						notAllowed = append(notAllowed, leaf)
					}
				}
				assert.Equal(t, want, len(result.DeniedLicenses) == 0, "denied: %v", licenseStrings(result.DeniedLicenses))
				assert.ElementsMatch(t, wantAllowed, licenseStrings(result.AllowedLicenses), "allowed")
				// which of the failing leaves are blamed is checked exactly by TestEvaluate_PropertyAgainstReference
				assert.Subset(t, notAllowed, licenseStrings(result.DeniedLicenses), "denied")
			})
		}
	}
}

func TestEvaluate_RealWorldExpressions(t *testing.T) {
	// expressions as published by popular packages, against policies people actually write
	permissive := []string{"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD", "Zlib", "Unlicense", "CC0-1.0"}
	tests := []struct {
		name       string
		expression string
		allow      []string
		wantDenied []string
	}{
		// crates.io
		{name: "serde", expression: "MIT OR Apache-2.0", allow: []string{"MIT"}},
		{name: "serde, Apache only", expression: "MIT OR Apache-2.0", allow: []string{"Apache-2.0"}},
		{name: "serde, neither", expression: "MIT OR Apache-2.0", allow: []string{"ISC"}, wantDenied: []string{"MIT", "Apache-2.0"}},
		{name: "unicode-ident", expression: "(MIT OR Apache-2.0) AND Unicode-3.0", allow: permissive, wantDenied: []string{"Unicode-3.0"}},
		{name: "unicode-ident with Unicode allowed", expression: "(MIT OR Apache-2.0) AND Unicode-3.0", allow: []string{"MIT", "Unicode-3.0"}},
		{name: "rustix", expression: "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT", allow: []string{"MIT"}},
		{name: "rustix, only the exception form allowed", expression: "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT", allow: []string{"Apache-2.0 WITH LLVM-exception"}},
		// a glob is matched against the leaf text, and "Apache-*" covers the text of the WITH leaf too
		{name: "rustix, a glob on the license also matches its exception form", expression: "Apache-2.0 WITH LLVM-exception", allow: []string{"Apache-*"}},
		{name: "memchr", expression: "Unlicense OR MIT", allow: []string{"MIT"}},
		{name: "bytemuck", expression: "Zlib OR Apache-2.0 OR MIT", allow: []string{"Zlib"}},
		{name: "ring", expression: "Apache-2.0 AND ISC", allow: []string{"Apache-2.0"}, wantDenied: []string{"ISC"}},
		{name: "ring, both allowed", expression: "Apache-2.0 AND ISC", allow: permissive},
		{name: "encoding_rs", expression: "(Apache-2.0 OR MIT) AND BSD-3-Clause", allow: permissive},
		{name: "ryu", expression: "Apache-2.0 OR BSL-1.0", allow: []string{"BSL-1.0"}},

		// npm
		{name: "npm parenthesized OR", expression: "(MIT OR Apache-2.0)", allow: []string{"Apache-2.0"}},
		{name: "pako", expression: "(MIT AND Zlib)", allow: []string{"MIT"}, wantDenied: []string{"Zlib"}},
		{name: "rc", expression: "(BSD-2-Clause OR MIT OR Apache-2.0)", allow: []string{"Apache-2.0"}},
		{name: "type-fest", expression: "(MIT OR CC0-1.0)", allow: []string{"CC0-1.0"}},
		{name: "jszip", expression: "(MIT OR GPL-3.0-or-later)", allow: []string{"MIT"}},
		{name: "jszip, GPL only", expression: "(MIT OR GPL-3.0-or-later)", allow: []string{"GPL-3.0-only"}},
		{name: "path-is-inside", expression: "(WTFPL OR MIT)", allow: permissive},
		{name: "dompurify", expression: "(MPL-2.0 OR Apache-2.0)", allow: []string{"MPL-2.0"}},

		// Maven Central
		{name: "jakarta EE", expression: "EPL-2.0 OR GPL-2.0-only WITH Classpath-exception-2.0", allow: []string{"EPL-2.0"}},
		{name: "jakarta EE, Classpath form allowed", expression: "EPL-2.0 OR GPL-2.0-only WITH Classpath-exception-2.0", allow: []string{"GPL-2.0-only WITH Classpath-exception-2.0"}},
		{name: "jakarta EE, bare GPL is not enough", expression: "EPL-2.0 OR GPL-2.0-only WITH Classpath-exception-2.0", allow: []string{"GPL-2.0-only"}, wantDenied: []string{"EPL-2.0", "GPL-2.0-only WITH Classpath-exception-2.0"}},
		{name: "jaxb", expression: "CDDL-1.1 OR GPL-2.0-only WITH Classpath-exception-2.0", allow: []string{"CDDL-1.1"}},
		{name: "logback", expression: "EPL-1.0 OR LGPL-2.1-only", allow: []string{"LGPL-*"}},

		// PyPI (PEP 639 License-Expression)
		{name: "cryptography", expression: "Apache-2.0 OR BSD-3-Clause", allow: []string{"BSD-3-Clause"}},
		{name: "matplotlib", expression: "PSF-2.0 AND MIT AND BSD-3-Clause", allow: []string{"MIT", "BSD-3-Clause"}, wantDenied: []string{"PSF-2.0"}},

		// toolchains and system packages
		{name: "LLVM", expression: "Apache-2.0 WITH LLVM-exception", allow: []string{"Apache-2.0 WITH LLVM-exception"}},
		{name: "libgcc", expression: "GPL-3.0-or-later WITH GCC-exception-3.1", allow: []string{"GPL-3.0-or-later WITH GCC-exception-3.1"}},
		{name: "linux uapi headers", expression: "GPL-2.0-only WITH Linux-syscall-note", allow: []string{"GPL-2.0-only"}, wantDenied: []string{"GPL-2.0-only WITH Linux-syscall-note"}},
		{name: "glibc", expression: "LGPL-2.1-or-later", allow: []string{"LGPL-3.0-only"}},
		{name: "glibc, only the base version allowed", expression: "LGPL-2.1-or-later", allow: []string{"LGPL-2.1-only"}},
		{name: "perl", expression: "Artistic-1.0-Perl OR GPL-1.0-or-later", allow: []string{"GPL-2.0-only"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluateSyftLicenses(t, &Policy{Allow: tt.allow}, spdx(tt.expression))
			assert.ElementsMatch(t, tt.wantDenied, licenseStrings(result.DeniedLicenses))
		})
	}
}

func TestEvaluate_RequireKnownLicenseInExpressions(t *testing.T) {
	tests := []struct {
		name       string
		licenses   []pkg.License
		allow      []string
		wantDenied []string
		// wantUnknown is set when the reason must be the unknown-license one
		wantUnknown bool
	}{
		{name: "known alternative passes an OR with an unknown one", licenses: []pkg.License{spdx("LicenseRef-x OR MIT")}, allow: []string{"MIT"}},
		{name: "unknown alternative alone cannot pass, even when allowed", licenses: []pkg.License{spdx("LicenseRef-x OR GPL-3.0-only")}, allow: []string{"LicenseRef-x"}, wantDenied: []string{"LicenseRef-x", "GPL-3.0-only"}, wantUnknown: true},
		{name: "unknown under AND always fails", licenses: []pkg.License{spdx("MIT AND LicenseRef-x")}, allow: []string{"MIT", "LicenseRef-x"}, wantDenied: []string{"LicenseRef-x"}, wantUnknown: true},
		{name: "unknown inside a nested OR that has a known way out", licenses: []pkg.License{spdx("MIT AND (LicenseRef-x OR Apache-2.0)")}, allow: []string{"MIT", "Apache-2.0"}},
		{name: "unknown inside a nested OR with no known way out", licenses: []pkg.License{spdx("MIT AND (LicenseRef-x OR GPL-3.0-only)")}, allow: []string{"MIT", "LicenseRef-*"}, wantDenied: []string{"LicenseRef-x", "GPL-3.0-only"}, wantUnknown: true},
		{name: "OR of AND groups, the known group passes", licenses: []pkg.License{spdx("(LicenseRef-x AND MIT) OR (Apache-2.0 AND ISC)")}, allow: []string{"MIT", "Apache-2.0", "ISC", "LicenseRef-x"}},
		{name: "OR of AND groups, only the unknown group would pass", licenses: []pkg.License{spdx("(LicenseRef-x AND MIT) OR (Apache-2.0 AND GPL-3.0-only)")}, allow: []string{"MIT", "Apache-2.0", "LicenseRef-x"}, wantDenied: []string{"LicenseRef-x", "GPL-3.0-only"}, wantUnknown: true},
		{name: "DocumentRef is unknown", licenses: []pkg.License{spdx("DocumentRef-a:LicenseRef-b OR MIT")}, allow: []string{"MIT"}},
		{name: "DocumentRef alone is unknown", licenses: []pkg.License{spdx("DocumentRef-a:LicenseRef-b")}, allow: []string{"DocumentRef-a:LicenseRef-b"}, wantDenied: []string{"DocumentRef-a:LicenseRef-b"}, wantUnknown: true},
		{name: "a rejected expression is unknown", licenses: []pkg.License{spdx("MIT or Apache-2.0")}, allow: []string{"MIT or Apache-2.0"}, wantDenied: []string{"MIT or Apache-2.0"}, wantUnknown: true},
		{name: "unknown separate declaration fails the package", licenses: []pkg.License{spdx("MIT OR Apache-2.0"), {Value: "Custom License"}}, allow: []string{"MIT", "Custom License"}, wantDenied: []string{"Custom License"}, wantUnknown: true},
		{name: "non-SPDX value named like an SPDX id is unknown", licenses: []pkg.License{{Value: "MIT"}}, allow: []string{"MIT"}, wantDenied: []string{"MIT"}, wantUnknown: true},
		{name: "deprecated ids are known", licenses: []pkg.License{spdx("GPL-2.0 OR LicenseRef-x")}, allow: []string{"GPL-2.0"}},
		{name: "deprecated id with a built in exception is known", licenses: []pkg.License{spdx("GPL-2.0-with-classpath-exception")}, allow: []string{"GPL-2.0-with-classpath-exception"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluateSyftLicenses(t, &Policy{Allow: tt.allow, RequireKnownLicense: true}, tt.licenses...)
			assert.ElementsMatch(t, tt.wantDenied, licenseStrings(result.DeniedLicenses))
			if tt.wantUnknown {
				assert.Contains(t, result.Reason, "unknown licenses")
			}
		})
	}
}

func TestEvaluate_PatternsPerLeaf(t *testing.T) {
	// allow entries are globs (filepath.Match) or regex-ish (".*", ".+"), matched against each leaf
	tests := []struct {
		name       string
		expression string
		allow      []string
		wantDenied []string
	}{
		{name: "glob picks one alternative", expression: "GPL-3.0-only OR BSD-3-Clause", allow: []string{"BSD-*"}},
		{name: "regex style any", expression: "GPL-3.0-only OR BSD-3-Clause", allow: []string{"BSD.*"}},
		{name: "regex style one or more", expression: "GPL-3.0-only OR BSD-3-Clause", allow: []string{"BSD.+"}},
		{name: "glob must cover every AND operand", expression: "BSD-2-Clause AND MIT", allow: []string{"BSD-*"}, wantDenied: []string{"MIT"}},
		{name: "suffix glob", expression: "GPL-2.0-only OR GPL-3.0-or-later", allow: []string{"*-only"}},
		{name: "single character glob", expression: "GPL-2.0-only AND GPL-3.0-only", allow: []string{"GPL-?.0-only"}},
		{name: "character class glob", expression: "MIT OR ISC", allow: []string{"[I]SC"}},
		{name: "star allows any leaf", expression: "LicenseRef-x AND DocumentRef-a:LicenseRef-b AND GPL-3.0-only", allow: []string{"*"}},
		{name: "glob over the WITH leaf text", expression: "Apache-2.0 WITH LLVM-exception", allow: []string{"Apache-2.0 WITH *"}},
		{name: "glob over LicenseRefs", expression: "LicenseRef-a OR LicenseRef-b", allow: []string{"LicenseRef-b*"}},
		{name: "glob is case sensitive", expression: "MIT OR ISC", allow: []string{"mit*"}, wantDenied: []string{"MIT", "ISC"}},
		{name: "glob is not a range target", expression: "GPL-2.0-or-later", allow: []string{"GPL-3.0-*"}, wantDenied: []string{"GPL-2.0-or-later"}},
		{name: "glob does match the or-later text", expression: "GPL-2.0-or-later", allow: []string{"GPL-*"}},
		{name: "malformed glob matches nothing", expression: "MIT OR ISC", allow: []string{"[MIT"}, wantDenied: []string{"MIT", "ISC"}},
		{name: "glob never sees the whole expression", expression: "MIT OR GPL-3.0-only", allow: []string{"MIT OR *"}, wantDenied: []string{"MIT", "GPL-3.0-only"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluateSyftLicenses(t, &Policy{Allow: tt.allow}, spdx(tt.expression))
			assert.ElementsMatch(t, tt.wantDenied, licenseStrings(result.DeniedLicenses))
		})
	}
}

func TestEvaluate_ExpressionReporting(t *testing.T) {
	tests := []struct {
		name        string
		licenses    []pkg.License
		allow       []string
		wantAllowed []string
		wantDenied  []string
		wantReason  string
	}{
		{
			name:     "unused alternative is in neither list",
			licenses: []pkg.License{spdx("MIT OR GPL-3.0-only")}, allow: []string{"MIT"},
			wantAllowed: []string{"MIT"}, wantReason: "all licenses allowed",
		},
		{
			name:     "both alternatives allowed are both listed",
			licenses: []pkg.License{spdx("MIT OR Apache-2.0")}, allow: []string{"MIT", "Apache-2.0"},
			wantAllowed: []string{"MIT", "Apache-2.0"}, wantReason: "all licenses allowed",
		},
		{
			name:     "failing OR lists every alternative as denied",
			licenses: []pkg.License{spdx("GPL-3.0-only OR AGPL-3.0-only")}, allow: []string{"MIT"},
			wantDenied: []string{"GPL-3.0-only", "AGPL-3.0-only"}, wantReason: "package denied due to 2 denied licenses",
		},
		{
			name:     "failing AND lists allowed operands as allowed",
			licenses: []pkg.License{spdx("MIT AND GPL-3.0-only")}, allow: []string{"MIT"},
			wantAllowed: []string{"MIT"}, wantDenied: []string{"GPL-3.0-only"}, wantReason: "package denied due to 1 denied licenses",
		},
		{
			name:     "an alternative unused in a passing declaration is denied when another declaration needs it",
			licenses: []pkg.License{spdx("MIT OR GPL-3.0-only"), spdx("GPL-3.0-only AND Apache-2.0")}, allow: []string{"MIT", "Apache-2.0"},
			wantAllowed: []string{"MIT", "Apache-2.0"}, wantDenied: []string{"GPL-3.0-only"}, wantReason: "package denied due to 1 denied licenses",
		},
		{
			name:     "an allowed license is not denied because it also sits in a failing declaration",
			licenses: []pkg.License{spdx("MIT"), spdx("MIT AND GPL-3.0-only")}, allow: []string{"MIT"},
			wantAllowed: []string{"MIT"}, wantDenied: []string{"GPL-3.0-only"}, wantReason: "package denied due to 1 denied licenses",
		},
		{
			name:     "the same unused alternative in two passing declarations stays unlisted",
			licenses: []pkg.License{spdx("MIT OR GPL-3.0-only"), spdx("Apache-2.0 OR GPL-3.0-only")}, allow: []string{"MIT", "Apache-2.0"},
			wantAllowed: []string{"MIT", "Apache-2.0"}, wantReason: "all licenses allowed",
		},
		{
			name:     "duplicate atoms are listed once",
			licenses: []pkg.License{spdx("MIT AND (MIT OR GPL-3.0-only) AND MIT")}, allow: []string{"MIT"},
			wantAllowed: []string{"MIT"}, wantReason: "all licenses allowed",
		},
		{
			name:     "range allowed leaf is listed allowed",
			licenses: []pkg.License{spdx("GPL-2.0-or-later OR MIT")}, allow: []string{"GPL-3.0-only"},
			wantAllowed: []string{"GPL-2.0-or-later"}, wantReason: "all licenses allowed",
		},
		{
			name:     "content hash licenses are dropped",
			licenses: []pkg.License{{Value: "sha256:0123"}, spdx("MIT OR GPL-3.0-only")}, allow: []string{"MIT"},
			wantAllowed: []string{"MIT"}, wantReason: "all licenses allowed",
		},
		{
			// syft puts the expression in both fields, but grant only reads SPDXExpression
			name:     "Value does not change what an expression means",
			licenses: []pkg.License{{Value: "GPL-3.0-only", SPDXExpression: "MIT OR GPL-3.0-only"}}, allow: []string{"MIT"},
			wantAllowed: []string{"MIT"}, wantReason: "all licenses allowed",
		},
		{
			name:     "a rejected expression is one license",
			licenses: []pkg.License{spdx("MIT or GPL-3.0-only")}, allow: []string{"MIT"},
			wantDenied: []string{"MIT or GPL-3.0-only"}, wantReason: "package denied due to 1 denied licenses",
		},
		{
			// a non-SPDX value that looks like an expression is not parsed
			name:     "non-SPDX value is not an expression",
			licenses: []pkg.License{{Value: "MIT OR GPL-3.0-only"}}, allow: []string{"MIT"},
			wantDenied: []string{"MIT OR GPL-3.0-only"}, wantReason: "package denied due to 1 denied licenses",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluateSyftLicenses(t, &Policy{Allow: tt.allow}, tt.licenses...)
			assert.ElementsMatch(t, tt.wantAllowed, licenseStrings(result.AllowedLicenses), "allowed")
			assert.ElementsMatch(t, tt.wantDenied, licenseStrings(result.DeniedLicenses), "denied")
			assert.Equal(t, tt.wantReason, result.Reason)
		})
	}
}

func TestEvaluate_ExpressionPackageRules(t *testing.T) {
	t.Run("ignore-packages wins over a failing expression", func(t *testing.T) {
		result := evaluateEntries(t, &Policy{Allow: []string{"MIT"}, IgnorePackages: []string{"pkg"}, RequireKnownLicense: true},
			[][]pkg.License{{spdx("GPL-3.0-only AND LicenseRef-x")}})
		require.Len(t, result.IgnoredPackages, 1)
		assert.Empty(t, result.DeniedPackages)
		assert.Empty(t, result.AllowedPackages)
	})
	t.Run("require-license denies a package whose only license is a content hash", func(t *testing.T) {
		result := evaluateEntries(t, &Policy{Allow: []string{"*"}, RequireLicense: true}, [][]pkg.License{{{Value: "sha256:0123"}}})
		require.Len(t, result.DeniedPackages, 1)
	})
	t.Run("require-license is satisfied by a passing expression", func(t *testing.T) {
		result := evaluateEntries(t, &Policy{Allow: []string{"MIT"}, RequireLicense: true}, [][]pkg.License{{spdx("MIT OR GPL-3.0-only")}})
		require.Len(t, result.AllowedPackages, 1)
	})
	t.Run("an empty allow list denies every alternative", func(t *testing.T) {
		result := evaluateEntries(t, &Policy{}, [][]pkg.License{{spdx("MIT OR Apache-2.0")}})
		require.Len(t, result.DeniedPackages, 1)
		assert.ElementsMatch(t, []string{"MIT", "Apache-2.0"}, licenseStrings(result.DeniedPackages[0].DeniedLicenses))
	})
}

func TestEvaluate_MergedDuplicatePackages(t *testing.T) {
	tests := []struct {
		name string
		// sboms holds one SBOM per entry, each with the cataloged entries of the same package
		sboms      [][][]pkg.License
		allow      []string
		wantDenied []string // nil means the merged package passes
	}{
		{
			name:  "two entries with OR expressions that both pass",
			sboms: [][][]pkg.License{{{spdx("MIT OR GPL-3.0-only")}, {spdx("Apache-2.0 OR MIT")}}},
			allow: []string{"MIT"},
		},
		{
			name:       "one entry with an OR, the other with its unused alternative alone",
			sboms:      [][][]pkg.License{{{spdx("MIT OR GPL-3.0-only")}, {spdx("GPL-3.0-only")}}},
			allow:      []string{"MIT"},
			wantDenied: []string{"GPL-3.0-only"},
		},
		{
			name:       "same package in two SBOMs",
			sboms:      [][][]pkg.License{{{spdx("MIT OR GPL-3.0-only")}}, {{spdx("GPL-3.0-only AND MIT")}}},
			allow:      []string{"MIT"},
			wantDenied: []string{"GPL-3.0-only"},
		},
		{
			name:  "an entry with no license does not weaken the other",
			sboms: [][][]pkg.License{{{spdx("MIT OR GPL-3.0-only")}, {}}},
			allow: []string{"MIT"},
		},
		{
			name:       "an entry with no license does not rescue the other",
			sboms:      [][][]pkg.License{{{spdx("ISC OR GPL-3.0-only")}, {}}},
			allow:      []string{"MIT"},
			wantDenied: []string{"ISC", "GPL-3.0-only"},
		},
		{
			name:       "each entry's unknown atom is judged",
			sboms:      [][][]pkg.License{{{spdx("MIT OR LicenseRef-a")}, {spdx("LicenseRef-a AND MIT")}}},
			allow:      []string{"MIT"},
			wantDenied: []string{"LicenseRef-a"},
		},
		{
			name:  "differently spelled copies of the same expression",
			sboms: [][][]pkg.License{{{spdx("mit OR gpl-3.0-only")}, {spdx("MIT OR GPL-3.0-only")}}},
			allow: []string{"MIT"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluateEntries(t, &Policy{Allow: tt.allow}, tt.sboms...)
			require.Equal(t, 1, result.Summary.TotalPackages, "entries must merge")
			if tt.wantDenied == nil {
				require.Len(t, result.AllowedPackages, 1, "denied: %+v", result.DeniedPackages)
				return
			}
			require.Len(t, result.DeniedPackages, 1)
			assert.ElementsMatch(t, tt.wantDenied, licenseStrings(result.DeniedPackages[0].DeniedLicenses))
		})
	}
}

func TestLicenseMatcher_RangeFamilies(t *testing.T) {
	// declared side ranges across the license families in go-spdx's range table
	// (spdxlicenses/license_ranges.go). Versions are compared within one family only.
	tests := []struct {
		declared string
		allow    string
		want     bool
	}{
		// GPL, including the deprecated "+" ids (Annex A.3)
		{"GPL-1.0-or-later", "GPL-3.0-only", true},
		{"GPL-1.0+", "GPL-2.0-only", true},
		{"GPL-2.0+", "GPL-2.0-or-later", true},
		{"GPL-3.0+", "GPL-3.0-only", true},
		{"GPL-3.0", "GPL-3.0-only", true},
		{"GPL-2.0-or-later", "GPL-2.0", true},
		{"GPL-3.0-or-later", "GPL-2.0-only", false},
		{"GPL-2.0-or-later", "LGPL-3.0-only", false},

		// LGPL
		{"LGPL-2.0+", "LGPL-2.1-only", true},
		{"LGPL-2.1+", "LGPL-2.1", true},
		{"LGPL-2.0-or-later", "LGPL-3.0-only", true},
		{"LGPL-3.0+", "LGPL-2.1-only", false},
		{"LGPL-2.1-only", "LGPL-3.0-only", false},
		{"LGPL-2.1-or-later", "GPL-3.0-only", false},

		// AGPL
		{"AGPL-1.0-or-later", "AGPL-3.0-only", true},
		{"AGPL-3.0-or-later", "AGPL-3.0-only", true},
		{"AGPL-3.0-or-later", "GPL-3.0-only", false},

		// GFDL
		{"GFDL-1.1-or-later", "GFDL-1.3-only", true},
		{"GFDL-1.2-or-later", "GFDL-1.1-only", false},

		// families with no or-later ids, so "+" is kept on the atom
		{"Apache-1.1+", "Apache-2.0", true},
		{"Apache-2.0+", "Apache-1.1", false},
		{"MPL-1.1+", "MPL-2.0", true},
		{"MPL-2.0+", "MPL-2.0", true},
		{"MPL-1.0+", "MPL-1.1", true},
		{"EPL-1.0+", "EPL-2.0", true},
		{"CC-BY-3.0+", "CC-BY-4.0", true},
		{"CC-BY-4.0+", "CC-BY-3.0", false},
		{"CC-BY-SA-3.0+", "CC-BY-4.0", false},
		{"OLDAP-2.0+", "OLDAP-2.8", true},
		{"CDDL-1.0+", "CDDL-1.1", true},
		{"Artistic-1.0+", "Artistic-2.0", true},
		{"OSL-1.0+", "OSL-3.0", true},
		{"LPPL-1.0+", "LPPL-1.3c", true},

		// no range table entry
		{"BSD-2-Clause+", "BSD-3-Clause", false},
		{"MIT+", "MIT", true},

		// go-spdx keeps MPL-2.0-no-copyleft-exception in a separate group, and finds MPL-1.1 in the first
		{"MPL-1.1+", "MPL-2.0-no-copyleft-exception", false},

		// go-spdx groups these unrelated licenses as versions of one family, so a "+" reaches across
		{"Brian-Gladman-2-Clause+", "Brian-Gladman-3-Clause", true},

		// a "+" on an id that already states its range is not a range, the id is exact
		{"GPL-2.0-only+", "GPL-3.0-only", false},
		{"GPL-2.0-only+", "GPL-2.0-only", true},
		{"LGPL-2.1-only+", "LGPL-3.0-only", false},

		// plain ids are never widened by the range table
		{"MIT", "MIT-0", false},
		{"BSD-3-Clause", "BSD-2-Clause", false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s allowed by %s", tt.declared, tt.allow), func(t *testing.T) {
			result := evaluateSyftLicenses(t, &Policy{Allow: []string{tt.allow}}, spdx(tt.declared))
			assert.Equal(t, tt.want, len(result.DeniedLicenses) == 0, "denied: %v", licenseStrings(result.DeniedLicenses))
		})
	}
}

func TestLicenseMatcher_RangesInsideExpressions(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		allow      []string
		wantDenied []string
	}{
		{name: "range alternative passes an OR", expression: "LGPL-2.1+ OR SSPL-1.0", allow: []string{"LGPL-3.0-only"}},
		{name: "range operand passes an AND", expression: "GPL-2.0-or-later AND MIT", allow: []string{"GPL-3.0-only", "MIT"}},
		{name: "plus kept on the atom passes an AND", expression: "MPL-1.1+ AND MIT", allow: []string{"MPL-2.0", "MIT"}},
		{name: "only is still exact inside an OR", expression: "GPL-2.0-only OR SSPL-1.0", allow: []string{"GPL-3.0-only"}, wantDenied: []string{"GPL-2.0-only", "SSPL-1.0"}},
		{name: "range allow entry is literal inside an OR", expression: "GPL-3.0-only OR SSPL-1.0", allow: []string{"GPL-2.0-or-later"}, wantDenied: []string{"GPL-3.0-only", "SSPL-1.0"}},
		{name: "range on one side, exception on the other", expression: "GPL-2.0-or-later OR Apache-2.0 WITH LLVM-exception", allow: []string{"GPL-3.0-only"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluateSyftLicenses(t, &Policy{Allow: tt.allow}, spdx(tt.expression))
			assert.ElementsMatch(t, tt.wantDenied, licenseStrings(result.DeniedLicenses))
		})
	}
}

// spec edge cases that are easy to get wrong. Each is what the spec, or grant's documented reading of
// it, calls for. The ones still skipped are known gaps that need an upstream go-spdx fix.
func TestEvaluate_SpecEdgeCases(t *testing.T) {
	t.Run("WITH expression is a known license under require-known-license", func(t *testing.T) {
		result := evaluateSyftLicenses(t, &Policy{Allow: []string{"Apache-2.0 WITH LLVM-exception"}, RequireKnownLicense: true}, spdx("Apache-2.0 WITH LLVM-exception"))
		assert.Empty(t, result.DeniedLicenses)
	})
	t.Run("range applies to a license with an exception", func(t *testing.T) {
		result := evaluateSyftLicenses(t, &Policy{Allow: []string{"GPL-3.0-only WITH Classpath-exception-2.0"}}, spdx("GPL-2.0-or-later WITH Classpath-exception-2.0"))
		assert.Empty(t, result.DeniedLicenses)
	})
	t.Run("deprecated id equals its only form with an exception", func(t *testing.T) {
		result := evaluateSyftLicenses(t, &Policy{Allow: []string{"GPL-2.0-only WITH Classpath-exception-2.0"}}, spdx("GPL-2.0 WITH Classpath-exception-2.0"))
		assert.Empty(t, result.DeniedLicenses)
	})
	t.Run("a range allowed leaf in a failing declaration is not reported denied", func(t *testing.T) {
		result := evaluateSyftLicenses(t, &Policy{Allow: []string{"MPL-2.0"}}, spdx("MPL-1.1+ AND GPL-3.0-only"))
		assert.ElementsMatch(t, []string{"GPL-3.0-only"}, licenseStrings(result.DeniedLicenses))
	})
	t.Run("a non-SPDX declaration does not become known by sharing a name with an SPDX license", func(t *testing.T) {
		// for comparison, the same non-SPDX value alone (or next to plain "MIT") is denied as unknown
		result := evaluateSyftLicenses(t, &Policy{Allow: []string{"MIT"}, RequireKnownLicense: true}, pkg.License{Value: "MIT"}, spdx("GPL-3.0-only OR MIT"))
		assert.NotEmpty(t, result.DeniedLicenses)
	})
	t.Run("a range allowed leaf does not hide the exact form of the same license", func(t *testing.T) {
		policy := &Policy{Allow: []string{"MPL-2.0", "Apache-2.0"}}
		for _, declarations := range [][]pkg.License{
			{spdx("MPL-1.1+ AND MPL-1.1")},
			{spdx("MPL-1.1+"), spdx("MPL-1.1")},
			{spdx("Apache-1.0+ AND Apache-1.0")},
		} {
			result := evaluateSyftLicenses(t, policy, declarations...)
			assert.NotEmpty(t, result.DeniedLicenses, "%v", declarations)
			assert.Empty(t, result.AllowedLicenses, "%v", declarations)
		}
	})
	t.Run("an id glued to an operator after a plus requires every license", func(t *testing.T) {
		// go-spdx ends the id at "+" and reads "GPL-3.0+ANDMIT" as two licenses, grant's parser reads one id
		for _, expression := range []string{"GPL-3.0+ANDMIT", "MIT AND AGPL-3.0+ANDMIT"} {
			result := evaluateSyftLicenses(t, &Policy{Allow: []string{"MIT"}}, spdx(expression))
			assert.NotEmpty(t, result.DeniedLicenses, "%q", expression)
		}
	})
	t.Run("nesting past the depth cap requires every license", func(t *testing.T) {
		depth := maxExpressionDepth + 1
		expression := strings.Repeat("(", depth) + "MIT OR GPL-3.0-only" + strings.Repeat(")", depth)
		result := evaluateSyftLicenses(t, &Policy{Allow: []string{"MIT"}}, spdx(expression))
		assert.ElementsMatch(t, []string{"GPL-3.0-only"}, licenseStrings(result.DeniedLicenses))
	})
	t.Run("GFDL invariants versions are ranges", func(t *testing.T) {
		t.Skip("known gap: go-spdx v2.7.0 has no range group for GFDL-*-invariants (or no-invariants), so or-later never reaches a later version")
		result := evaluateSyftLicenses(t, &Policy{Allow: []string{"GFDL-1.3-invariants-only"}}, spdx("GFDL-1.1-invariants-or-later"))
		assert.Empty(t, result.DeniedLicenses)
	})
}

// the property tests below generate random declarations and allow lists with a fixed seed, and
// compare grant against reference evaluators written here from the spec and grant's documented
// reading of it (license_expression.go, licenseMatcher)

// propertyLeaf is one leaf the generator can use, with what the reference needs to judge it
type propertyLeaf struct {
	// text is how the leaf is written in the expression
	text string
	// flat is the String() of the license grant flattens the leaf into
	flat string
	// names are matched against allow entries literally and as globs (the flattened license, plus
	// the atom when it keeps a "+" the flattened license drops)
	names []string
	// known is false for leaves grant treats as non-SPDX
	known bool
	// ranges are allow entries that satisfy the leaf as a declared range
	ranges []string
	// isWith marks a leaf with an exception, which the spec treats as known
	isWith bool
}

var propertyLeaves = []propertyLeaf{
	{text: "MIT", flat: "MIT", names: []string{"MIT"}, known: true},
	{text: "mit", flat: "MIT", names: []string{"MIT"}, known: true},
	{text: "Apache-2.0", flat: "Apache-2.0", names: []string{"Apache-2.0"}, known: true},
	{text: "ISC", flat: "ISC", names: []string{"ISC"}, known: true},
	{text: "BSD-3-Clause", flat: "BSD-3-Clause", names: []string{"BSD-3-Clause"}, known: true},
	{text: "GPL-3.0-only", flat: "GPL-3.0-only", names: []string{"GPL-3.0-only"}, known: true},
	{text: "LGPL-2.1-only", flat: "LGPL-2.1-only", names: []string{"LGPL-2.1-only"}, known: true},
	{text: "GPL-2.0-or-later", flat: "GPL-2.0-or-later", names: []string{"GPL-2.0-or-later"}, known: true,
		ranges: []string{"GPL-2.0-only", "GPL-3.0-only"}},
	{text: "GPL-2.0+", flat: "GPL-2.0-or-later", names: []string{"GPL-2.0-or-later"}, known: true,
		ranges: []string{"GPL-2.0-only", "GPL-3.0-only"}},
	{text: "MPL-1.1+", flat: "MPL-1.1", names: []string{"MPL-1.1", "MPL-1.1+"}, known: true, ranges: []string{"MPL-2.0"}},
	// shares its flattened license with "MPL-1.1+", but is exact
	{text: "MPL-1.1", flat: "MPL-1.1", names: []string{"MPL-1.1"}, known: true},
	{text: "Apache-2.0 WITH LLVM-exception", flat: "Apache-2.0 WITH LLVM-exception", names: []string{"Apache-2.0 WITH LLVM-exception"}, known: true, isWith: true},
	{text: "LicenseRef-a", flat: "LicenseRef-a", names: []string{"LicenseRef-a"}},
	{text: "LicenseRef-b.c", flat: "LicenseRef-b.c", names: []string{"LicenseRef-b.c"}},
	{text: "DocumentRef-d:LicenseRef-e", flat: "DocumentRef-d:LicenseRef-e", names: []string{"DocumentRef-d:LicenseRef-e"}},
}

var propertyAllowEntries = []string{
	"MIT", "Apache-2.0", "ISC", "GPL-3.0-only", "GPL-2.0-only", "MPL-2.0", "LicenseRef-a", "BSD-*", "*-only",
	"Apache-2.0 WITH LLVM-exception", "GPL-2.0-or-later", "LicenseRef-*", "MPL-1.1+", "mit", "*",
}

// propertyTerm is a generated expression tree
type propertyTerm struct {
	op    string
	terms []propertyTerm
	leaf  *propertyLeaf
}

func generateTerm(r *rand.Rand, depth int) propertyTerm {
	if depth == 0 || r.IntN(3) == 0 {
		return propertyTerm{leaf: &propertyLeaves[r.IntN(len(propertyLeaves))]}
	}
	op := opAND
	if r.IntN(2) == 0 {
		op = opOR
	}
	n := 2 + r.IntN(2)
	terms := make([]propertyTerm, 0, n)
	for range n {
		terms = append(terms, generateTerm(r, depth-1))
	}
	return propertyTerm{op: op, terms: terms}
}

// render writes the tree as an expression, adding parentheses where precedence needs them and at
// random elsewhere, with random runs of spaces
func (pt propertyTerm) render(r *rand.Rand) string {
	space := func() string { return strings.Repeat(" ", 1+r.IntN(2)) }
	paren := func(s string) string {
		if r.IntN(2) == 0 {
			return "(" + s + ")"
		}
		return "(" + space() + s + space() + ")"
	}
	if pt.leaf != nil {
		if r.IntN(6) == 0 {
			return paren(pt.leaf.text)
		}
		return pt.leaf.text
	}
	parts := make([]string, 0, len(pt.terms))
	for _, term := range pt.terms {
		s := term.render(r)
		// an OR under an AND needs parentheses, anything else may get them
		if term.leaf == nil && ((pt.op == opAND && term.op == opOR) || r.IntN(4) == 0) {
			s = paren(s)
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, space()+pt.op+space())
}

func (pt propertyTerm) eval(leafAllowed func(propertyLeaf) bool) bool {
	switch pt.op {
	case opAND:
		for _, term := range pt.terms {
			if !term.eval(leafAllowed) {
				return false
			}
		}
		return true
	case opOR:
		for _, term := range pt.terms {
			if term.eval(leafAllowed) {
				return true
			}
		}
		return false
	default:
		return leafAllowed(*pt.leaf)
	}
}

// blame is the reference for which leaves a failed term is reported denied for: a failing leaf is
// blamed for itself, a failing AND for its failing operands, and a failing OR for all of its operands
// (each of which failed). An operand that passed is never blamed.
func (pt propertyTerm) blame(leafAllowed func(propertyLeaf) bool, fn func(propertyLeaf)) {
	if pt.eval(leafAllowed) {
		return
	}
	if pt.leaf != nil {
		fn(*pt.leaf)
		return
	}
	for _, term := range pt.terms {
		term.blame(leafAllowed, fn)
	}
}

func (pt propertyTerm) eachLeaf(fn func(propertyLeaf)) {
	if pt.leaf != nil {
		fn(*pt.leaf)
		return
	}
	for _, term := range pt.terms {
		term.eachLeaf(fn)
	}
}

// matchesAllow is the reference for one allow entry: a literal match or a glob match
func matchesAllow(name string, allow []string) bool {
	for _, a := range allow {
		if ok, err := filepath.Match(a, name); a == name || (err == nil && ok) {
			return true
		}
	}
	return false
}

// propertyPolicy is the reference reading of a policy
type propertyPolicy struct {
	allow        []string
	requireKnown bool
	// withIsKnown treats WITH leaves as known licenses, as the spec does
	withIsKnown bool
}

func (p propertyPolicy) known(leaf propertyLeaf) bool {
	return leaf.known || (p.withIsKnown && leaf.isWith)
}

// leafAllowed judges a leaf of a declaration (with its range)
func (p propertyPolicy) leafAllowed(leaf propertyLeaf) bool {
	if p.requireKnown && !p.known(leaf) {
		return false
	}
	for _, name := range leaf.names {
		if matchesAllow(name, p.allow) {
			return true
		}
	}
	for _, target := range leaf.ranges {
		if slices.Contains(p.allow, target) {
			return true
		}
	}
	return false
}

// oldAllowed is the rule before OR was honored: every flattened license must match an allow entry
func (p propertyPolicy) oldAllowed(leaf propertyLeaf) bool {
	if p.requireKnown && !leaf.known {
		return false
	}
	return matchesAllow(leaf.flat, p.allow)
}

type propertyCase struct {
	declarations []propertyTerm
	expressions  []string
	policy       propertyPolicy
}

func generatePropertyCases(seed uint64, n int) []propertyCase {
	r := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)) //nolint:gosec // a fixed seed keeps the cases reproducible
	cases := make([]propertyCase, 0, n)
	for range n {
		var c propertyCase
		for range 1 + r.IntN(2) {
			term := generateTerm(r, 3)
			c.declarations = append(c.declarations, term)
			c.expressions = append(c.expressions, term.render(r))
		}
		for _, entry := range propertyAllowEntries {
			// "*" allows everything, keep it rare so most cases are interesting
			if (entry == "*" && r.IntN(20) == 0) || (entry != "*" && r.IntN(4) == 0) {
				c.policy.allow = append(c.policy.allow, entry)
			}
		}
		c.policy.requireKnown = r.IntN(3) == 0
		cases = append(cases, c)
	}
	return cases
}

func (c propertyCase) evaluate(t *testing.T) PackageResult {
	t.Helper()
	licenses := make([]pkg.License, 0, len(c.expressions))
	for _, expression := range c.expressions {
		licenses = append(licenses, spdx(expression))
	}
	return evaluateSyftLicenses(t, &Policy{Allow: c.policy.allow, RequireKnownLicense: c.policy.requireKnown}, licenses...)
}

func (c propertyCase) String() string {
	return fmt.Sprintf("declarations=%q allow=%q require-known=%v", c.expressions, c.policy.allow, c.policy.requireKnown)
}

func TestEvaluate_PropertyAgainstReference(t *testing.T) {
	cases := generatePropertyCases(20261002, 2000)
	var passed, failed, flipped int
	for _, c := range cases {
		result := c.evaluate(t)
		allowed := len(result.DeniedLicenses) == 0

		// monotonic: anything the old flatten-and-AND rule allowed is still allowed
		oldAllows := true
		for _, d := range c.declarations {
			d.eachLeaf(func(leaf propertyLeaf) {
				oldAllows = oldAllows && c.policy.oldAllowed(leaf)
			})
		}
		if oldAllows && !allowed {
			t.Errorf("not monotonic: the old rule allows %s, grant denies %v", c, licenseStrings(result.DeniedLicenses))
		}

		// sound: grant never allows what the boolean reading of the spec denies
		spec := c.policy
		spec.withIsKnown = true
		specAllows := true
		for _, d := range c.declarations {
			specAllows = specAllows && d.eval(spec.leafAllowed)
		}
		if allowed && !specAllows {
			t.Errorf("not sound: grant allows %s, the spec reading denies it", c)
		}

		// exact: grant agrees with the reference reading of its documented rules (ranges on the declared
		// side only, require-known-license per leaf, WITH leaves known)
		want := true
		for _, d := range c.declarations {
			want = want && d.eval(c.policy.leafAllowed)
		}
		if want != allowed {
			t.Errorf("disagrees with the reference: want allowed=%v for %s, denied %v", want, c, licenseStrings(result.DeniedLicenses))
			continue
		}

		// reporting, per flattened license: one that a blamed leaf of a failed declaration refers to
		// is listed denied, even when another leaf of the same license passes ("MPL-1.1+" vs
		// "MPL-1.1"). Otherwise it is listed allowed when any of its leaves passes, and left out of
		// both lists when it is only an unused alternative, or sits in an OR that passed.
		wantAllowed := map[string]bool{}
		wantDenied := map[string]bool{}
		for _, d := range c.declarations {
			d.blame(c.policy.leafAllowed, func(leaf propertyLeaf) {
				wantDenied[leaf.flat] = true
			})
			d.eachLeaf(func(leaf propertyLeaf) {
				if c.policy.leafAllowed(leaf) {
					wantAllowed[leaf.flat] = true
				}
			})
		}
		for flat := range wantDenied {
			delete(wantAllowed, flat)
		}
		if !assert.ElementsMatch(t, mapKeys(wantDenied), licenseStrings(result.DeniedLicenses), "denied for %s", c) ||
			!assert.ElementsMatch(t, mapKeys(wantAllowed), licenseStrings(result.AllowedLicenses), "allowed for %s", c) {
			continue
		}

		switch {
		case allowed && !oldAllows:
			flipped++
			passed++
		case allowed:
			passed++
		default:
			failed++
		}
	}
	// the generator must exercise both outcomes and the cases the change flips
	assert.Greater(t, passed, 200, "passing cases")
	assert.Greater(t, failed, 200, "failing cases")
	assert.Greater(t, flipped, 100, "cases the old rule denied and grant allows")
}

func TestEvaluate_PropertyRenderingDoesNotMatter(t *testing.T) {
	// the same tree written with different parentheses and spacing evaluates the same way
	r := rand.New(rand.NewPCG(7, 11)) //nolint:gosec // a fixed seed keeps the cases reproducible
	for _, c := range generatePropertyCases(42, 300) {
		want := c.evaluate(t)
		for i := range c.declarations {
			c.expressions[i] = c.declarations[i].render(r)
		}
		got := c.evaluate(t)
		assert.ElementsMatch(t, licenseStrings(want.DeniedLicenses), licenseStrings(got.DeniedLicenses), "%s", c)
		assert.ElementsMatch(t, licenseStrings(want.AllowedLicenses), licenseStrings(got.AllowedLicenses), "%s", c)
	}
}

func mapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
