package cli

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// these tests feed SPDX license expressions through real SBOM formats, so syft's decoding of each
// format (what lands in pkg.License Value and SPDXExpression) is part of what is tested:
//
//   - CycloneDX: `expression`, `license.id` and `license.name` all go through syft's license parser,
//     so a valid expression in `license.name` is an expression too. Separate entries are separate
//     declarations (AND)
//   - SPDX JSON: `licenseConcluded` and `licenseDeclared` are separate declarations, NOASSERTION and
//     NONE are dropped. syft trims a leading "LicenseRef-" from the whole field
//   - syft JSON: `value` and `spdxExpression` are taken as is

// packageFinding is the part of a JSON report finding these tests look at
type packageFinding struct {
	decision string
	licenses []string
}

// findingsByName runs grant on the SBOM with the policy and returns each package's finding
func findingsByName(t *testing.T, sbom, policy string) (map[string]packageFinding, int) {
	t.Helper()
	stdout, stderr, rc := runGrant(t, sbom, "-c", writeConfig(t, policy), "-o", "json", "check", "-")

	var report struct {
		Run struct {
			Targets []struct {
				Evaluation struct {
					Findings struct {
						Packages []struct {
							Name     string `json:"name"`
							Decision string `json:"decision"`
							Licenses []struct {
								ID string `json:"id"`
							} `json:"licenses"`
						} `json:"packages"`
					} `json:"findings"`
				} `json:"evaluation"`
			} `json:"targets"`
		} `json:"run"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &report), "stdout: %s\nstderr: %s", stdout, stderr)
	require.Len(t, report.Run.Targets, 1)

	findings := make(map[string]packageFinding)
	for _, p := range report.Run.Targets[0].Evaluation.Findings.Packages {
		f := packageFinding{decision: p.Decision}
		for _, l := range p.Licenses {
			f.licenses = append(f.licenses, l.ID)
		}
		findings[p.Name] = f
	}
	return findings, rc
}

type expressionCase struct {
	pkg          string
	wantDecision string
	// wantLicenses are the license ids in the finding: every license for an allowed package, only
	// the denied ones for a denied package. nil skips the check.
	wantLicenses []string
}

func assertFindings(t *testing.T, findings map[string]packageFinding, cases []expressionCase) {
	t.Helper()
	for _, c := range cases {
		f, ok := findings[c.pkg]
		if !assert.True(t, ok, "package %q missing from the report", c.pkg) {
			continue
		}
		assert.Equal(t, c.wantDecision, f.decision, "decision for %q", c.pkg)
		if c.wantLicenses != nil {
			assert.ElementsMatch(t, c.wantLicenses, f.licenses, "licenses for %q", c.pkg)
		}
	}
}

const cycloneDXExpressionsSBOM = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
{"type":"library","name":"expression-or","version":"1.0.0","licenses":[{"expression":"MIT OR GPL-3.0-only"}]},
{"type":"library","name":"expression-and","version":"1.0.0","licenses":[{"expression":"MIT AND GPL-3.0-only"}]},
{"type":"library","name":"and-of-or","version":"1.0.0","licenses":[{"expression":"(GPL-3.0-only OR MIT) AND (ISC OR MIT)"}]},
{"type":"library","name":"and-of-or-fails","version":"1.0.0","licenses":[{"expression":"(GPL-3.0-only OR MIT) AND (ISC OR AGPL-3.0-only)"}]},
{"type":"library","name":"name-holding-expression","version":"1.0.0","licenses":[{"license":{"name":"MIT OR GPL-3.0-only"}}]},
{"type":"library","name":"lower-case-id","version":"1.0.0","licenses":[{"license":{"id":"mit"}}]},
{"type":"library","name":"two-entries","version":"1.0.0","licenses":[{"license":{"id":"MIT"}},{"license":{"id":"GPL-3.0-only"}}]},
{"type":"library","name":"cargo-slash","version":"1.0.0","licenses":[{"license":{"name":"MIT/Apache-2.0"}}]},
{"type":"library","name":"with-or-chain","version":"1.0.0","licenses":[{"expression":"Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT"}]},
{"type":"library","name":"with-only","version":"1.0.0","licenses":[{"expression":"Apache-2.0 WITH LLVM-exception"}]},
{"type":"library","name":"lower-case-operator","version":"1.0.0","licenses":[{"expression":"MIT or GPL-3.0-only"}]},
{"type":"library","name":"noassertion-name","version":"1.0.0","licenses":[{"license":{"name":"NOASSERTION"}}]},
{"type":"library","name":"leading-space","version":"1.0.0","licenses":[{"expression":"  MIT OR GPL-3.0-only"}]},
{"type":"library","name":"licenseref-or","version":"1.0.0","licenses":[{"expression":"LicenseRef-foo OR MIT"}]},
{"type":"library","name":"documentref-or","version":"1.0.0","licenses":[{"expression":"DocumentRef-x:LicenseRef-foo OR MIT"}]},
{"type":"library","name":"range","version":"1.0.0","licenses":[{"expression":"GPL-2.0+ OR SSPL-1.0"}]},
{"type":"library","name":"unicode-ident","version":"1.0.0","licenses":[{"expression":"(MIT OR Apache-2.0) AND Unicode-3.0"}]}
]}`

func TestCheckCmdExpressionsCycloneDX(t *testing.T) {
	t.Run("allow MIT", func(t *testing.T) {
		findings, rc := findingsByName(t, cycloneDXExpressionsSBOM, "allow:\n  - MIT\n")
		assert.NotZero(t, rc)
		assertFindings(t, findings, []expressionCase{
			// a passing package still lists the unused alternative in its findings
			{pkg: "expression-or", wantDecision: "allow", wantLicenses: []string{"MIT", "GPL-3.0-only"}},
			{pkg: "expression-and", wantDecision: "deny", wantLicenses: []string{"GPL-3.0-only"}},
			{pkg: "and-of-or", wantDecision: "allow"},
			// a failing declaration is blamed on the operands that failed, the OR that passed is not listed
			{pkg: "and-of-or-fails", wantDecision: "deny", wantLicenses: []string{"ISC", "AGPL-3.0-only"}},
			{pkg: "name-holding-expression", wantDecision: "allow", wantLicenses: []string{"MIT", "GPL-3.0-only"}},
			{pkg: "lower-case-id", wantDecision: "allow", wantLicenses: []string{"MIT"}},
			{pkg: "two-entries", wantDecision: "deny", wantLicenses: []string{"GPL-3.0-only"}},
			{pkg: "cargo-slash", wantDecision: "deny", wantLicenses: []string{"MIT/Apache-2.0"}},
			{pkg: "with-or-chain", wantDecision: "allow"},
			{pkg: "with-only", wantDecision: "deny", wantLicenses: []string{"Apache-2.0 WITH LLVM-exception"}},
			{pkg: "lower-case-operator", wantDecision: "deny", wantLicenses: []string{"MIT or GPL-3.0-only"}},
			{pkg: "noassertion-name", wantDecision: "deny", wantLicenses: []string{"NOASSERTION"}},
			{pkg: "leading-space", wantDecision: "allow"},
			{pkg: "licenseref-or", wantDecision: "allow", wantLicenses: []string{"LicenseRef-foo", "MIT"}},
			{pkg: "documentref-or", wantDecision: "allow", wantLicenses: []string{"DocumentRef-x:LicenseRef-foo", "MIT"}},
			{pkg: "range", wantDecision: "deny", wantLicenses: []string{"GPL-2.0-or-later", "SSPL-1.0"}},
			{pkg: "unicode-ident", wantDecision: "deny", wantLicenses: []string{"Unicode-3.0"}},
		})
	})

	t.Run("allow MIT with require-known-license", func(t *testing.T) {
		findings, _ := findingsByName(t, cycloneDXExpressionsSBOM, "allow:\n  - MIT\n  - LicenseRef-*\nrequire-known-license: true\n")
		assertFindings(t, findings, []expressionCase{
			{pkg: "licenseref-or", wantDecision: "allow"},
			{pkg: "documentref-or", wantDecision: "allow"},
			{pkg: "cargo-slash", wantDecision: "deny"},
			{pkg: "noassertion-name", wantDecision: "deny"},
		})
	})

	t.Run("ranges and exceptions", func(t *testing.T) {
		findings, _ := findingsByName(t, cycloneDXExpressionsSBOM, "allow:\n  - GPL-3.0-only\n  - Apache-2.0 WITH LLVM-exception\n  - Unicode-3.0\n  - Apache-2.0\n")
		assertFindings(t, findings, []expressionCase{
			{pkg: "range", wantDecision: "allow", wantLicenses: []string{"GPL-2.0-or-later", "SSPL-1.0"}},
			{pkg: "with-only", wantDecision: "allow"},
			{pkg: "with-or-chain", wantDecision: "allow"},
			{pkg: "unicode-ident", wantDecision: "allow"},
			{pkg: "expression-or", wantDecision: "allow"},
			{pkg: "expression-and", wantDecision: "deny", wantLicenses: []string{"MIT"}},
		})
	})
}

func TestCheckCmdExpressionsDuplicateComponents(t *testing.T) {
	// the same package cataloged twice: every entry's declaration must pass
	tests := []struct {
		name         string
		licensesA    string
		licensesB    string
		wantDecision string
	}{
		{name: "both entries pass on MIT", licensesA: `[{"expression":"MIT OR GPL-3.0-only"}]`, licensesB: `[{"expression":"Apache-2.0 OR MIT"}]`, wantDecision: "allow"},
		{name: "the second entry needs the unused alternative", licensesA: `[{"expression":"MIT OR GPL-3.0-only"}]`, licensesB: `[{"license":{"id":"GPL-3.0-only"}}]`, wantDecision: "deny"},
		{name: "the second entry has no license", licensesA: `[{"expression":"MIT OR GPL-3.0-only"}]`, licensesB: `[]`, wantDecision: "allow"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sbom := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[` +
				`{"type":"library","name":"dup","version":"1.0.0","bom-ref":"a","licenses":` + tt.licensesA + `},` +
				`{"type":"library","name":"dup","version":"1.0.0","bom-ref":"b","licenses":` + tt.licensesB + `}]}`
			findings, _ := findingsByName(t, sbom, "allow:\n  - MIT\n")
			require.Len(t, findings, 1, "duplicates must merge")
			assertFindings(t, findings, []expressionCase{{pkg: "dup", wantDecision: tt.wantDecision}})
		})
	}
}

func spdxJSONSBOM(packages string) string {
	return `{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"test",` +
		`"documentNamespace":"https://example.com/test","creationInfo":{"created":"2024-01-01T00:00:00Z","creators":["Tool: test"]},` +
		`"packages":[` + packages + `]}`
}

func spdxJSONPackage(name, concluded, declared string) string {
	return `{"name":"` + name + `","SPDXID":"SPDXRef-` + name + `","versionInfo":"1.0.0","downloadLocation":"NOASSERTION",` +
		`"licenseConcluded":"` + concluded + `","licenseDeclared":"` + declared + `"}`
}

func TestCheckCmdExpressionsSPDXJSON(t *testing.T) {
	sbom := spdxJSONSBOM(spdxJSONPackage("declared-or", "NOASSERTION", "MIT OR GPL-3.0-only") + "," +
		spdxJSONPackage("declared-and", "NOASSERTION", "MIT AND GPL-3.0-only") + "," +
		spdxJSONPackage("concluded-and-declared", "GPL-3.0-only", "MIT OR GPL-3.0-only") + "," +
		spdxJSONPackage("concluded-narrows", "MIT", "MIT OR GPL-3.0-only") + "," +
		spdxJSONPackage("no-assertion", "NONE", "NOASSERTION") + "," +
		spdxJSONPackage("licenseref-last", "NOASSERTION", "MIT OR LicenseRef-foo") + "," +
		spdxJSONPackage("java-classpath", "NOASSERTION", "CDDL-1.1 OR GPL-2.0-only WITH Classpath-exception-2.0"))

	t.Run("allow MIT", func(t *testing.T) {
		findings, rc := findingsByName(t, sbom, "allow:\n  - MIT\n")
		assert.NotZero(t, rc)
		assertFindings(t, findings, []expressionCase{
			{pkg: "declared-or", wantDecision: "allow", wantLicenses: []string{"MIT", "GPL-3.0-only"}},
			{pkg: "declared-and", wantDecision: "deny", wantLicenses: []string{"GPL-3.0-only"}},
			// concluded and declared are separate declarations, and both must pass
			{pkg: "concluded-and-declared", wantDecision: "deny", wantLicenses: []string{"GPL-3.0-only"}},
			{pkg: "concluded-narrows", wantDecision: "allow"},
			// NOASSERTION and NONE are dropped, which leaves no license at all
			{pkg: "no-assertion", wantDecision: "allow", wantLicenses: []string{}},
			{pkg: "licenseref-last", wantDecision: "allow", wantLicenses: []string{"MIT", "LicenseRef-foo"}},
			{pkg: "java-classpath", wantDecision: "deny", wantLicenses: []string{"CDDL-1.1", "GPL-2.0-only WITH Classpath-exception-2.0"}},
		})
	})

	t.Run("require-license denies the package with no assertion", func(t *testing.T) {
		findings, _ := findingsByName(t, sbom, "allow:\n  - MIT\nrequire-license: true\n")
		assertFindings(t, findings, []expressionCase{
			{pkg: "no-assertion", wantDecision: "deny"},
			{pkg: "declared-or", wantDecision: "allow"},
		})
	})

	t.Run("Classpath alternative", func(t *testing.T) {
		findings, _ := findingsByName(t, sbom, "allow:\n  - GPL-2.0-only WITH Classpath-exception-2.0\n")
		assertFindings(t, findings, []expressionCase{{pkg: "java-classpath", wantDecision: "allow"}})
	})

	t.Run("LicenseRef as the first alternative", func(t *testing.T) {
		t.Skip("known gap (syft): spdxhelpers cleanSPDXID trims a leading \"LicenseRef-\" from the whole field, so \"LicenseRef-foo OR MIT\" " +
			"arrives as the invalid expression \"foo OR MIT\" and is judged as one non-SPDX license")
		findings, _ := findingsByName(t, spdxJSONSBOM(spdxJSONPackage("licenseref-first", "NOASSERTION", "LicenseRef-foo OR MIT")), "allow:\n  - MIT\n")
		assertFindings(t, findings, []expressionCase{{pkg: "licenseref-first", wantDecision: "allow"}})
	})
}

const syftJSONExpressionsSBOM = `{"artifacts":[
{"id":"a","name":"npm-or","version":"1.0.0","type":"npm","foundBy":"test","locations":[],"licenses":[{"value":"(MIT OR Apache-2.0)","spdxExpression":"(MIT OR Apache-2.0)","type":"declared","urls":[],"locations":[]}],"language":"javascript","cpes":[],"purl":""},
{"id":"b","name":"value-spoof","version":"1.0.0","type":"npm","foundBy":"test","locations":[],"licenses":[{"value":"MIT","spdxExpression":"MIT AND LicenseRef-evil","type":"declared","urls":[],"locations":[]}],"language":"javascript","cpes":[],"purl":""},
{"id":"d","name":"value-spoof-malformed","version":"1.0.0","type":"npm","foundBy":"test","locations":[],"licenses":[{"value":"MIT","spdxExpression":"GPL-3.0-only AND (","type":"declared","urls":[],"locations":[]}],"language":"javascript","cpes":[],"purl":""},
{"id":"c","name":"value-only","version":"1.0.0","type":"npm","foundBy":"test","locations":[],"licenses":[{"value":"MIT OR Apache-2.0","spdxExpression":"","type":"declared","urls":[],"locations":[]}],"language":"javascript","cpes":[],"purl":""}
],"artifactRelationships":[],"source":{"id":"s","name":"test","version":"","type":"unknown","metadata":null},"distro":{},"descriptor":{"name":"syft","version":"1.0.0"},"schema":{"version":"16.0.0","url":"https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.0.0.json"}}`

func TestCheckCmdExpressionsSyftJSON(t *testing.T) {
	findings, _ := findingsByName(t, syftJSONExpressionsSBOM, "allow:\n  - MIT\nrequire-known-license: true\n")
	assertFindings(t, findings, []expressionCase{
		{pkg: "npm-or", wantDecision: "allow", wantLicenses: []string{"MIT", "Apache-2.0"}},
		// value and spdxExpression are independent fields, value must not decide what the atoms are
		{pkg: "value-spoof", wantDecision: "deny", wantLicenses: []string{"LicenseRef-evil"}},
		// an expression that does not parse is named by itself, never by value
		{pkg: "value-spoof-malformed", wantDecision: "deny", wantLicenses: []string{"GPL-3.0-only AND ("}},
		// without spdxExpression the value is a license name, not an expression
		{pkg: "value-only", wantDecision: "deny", wantLicenses: []string{"MIT OR Apache-2.0"}},
	})
}

// the expressions and policies from https://github.com/mxmehl/grant-policy-testcases, one package per test
const policyTestcasesSBOM = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
{"type":"library","name":"test-1-or","version":"1.0.0","licenses":[{"expression":"Apache-2.0 OR GPL-3.0-or-later"}]},
{"type":"library","name":"test-2-with","version":"1.0.0","licenses":[{"expression":"GPL-2.0-only WITH Classpath-exception-2.0"}]},
{"type":"library","name":"test-3-with-and","version":"1.0.0","licenses":[{"expression":"GPL-2.0-only WITH Classpath-exception-2.0 AND MIT"}]},
{"type":"library","name":"test-4-nested","version":"1.0.0","licenses":[{"expression":"(Apache-2.0 AND (MIT OR GPL-2.0-only)) OR (EPL-2.0 AND 0BSD)"}]}
]}`

func TestCheckCmdPolicyTestcases(t *testing.T) {
	allow := "allow:\n  - MIT\n  - Apache-2.0\n  - BSD-2-Clause\n  - BSD-3-Clause\n  - 0BSD\n  - Unlicense\n  - PSF-2.0\n  - MPL-2.0\n"
	permissive := allow + "require-license: true\n"
	withGPL := allow + "  - GPL-2.0-only\n  - GPL-2.0-only WITH Classpath-exception-2.0\nrequire-license: true\n"

	t.Run("permissive policy (tests 1 and 4)", func(t *testing.T) {
		findings, _ := findingsByName(t, policyTestcasesSBOM, permissive)
		assertFindings(t, findings, []expressionCase{
			{pkg: "test-1-or", wantDecision: "allow"},
			{pkg: "test-4-nested", wantDecision: "allow"},
			// the exception form is not on this allow list
			{pkg: "test-2-with", wantDecision: "deny"},
			{pkg: "test-3-with-and", wantDecision: "deny", wantLicenses: []string{"GPL-2.0-only WITH Classpath-exception-2.0"}},
		})
	})

	t.Run("policy allowing the exception (tests 2 and 3)", func(t *testing.T) {
		findings, rc := findingsByName(t, policyTestcasesSBOM, withGPL)
		assert.Zero(t, rc)
		assertFindings(t, findings, []expressionCase{
			{pkg: "test-1-or", wantDecision: "allow"},
			{pkg: "test-2-with", wantDecision: "allow"},
			{pkg: "test-3-with-and", wantDecision: "allow"},
			{pkg: "test-4-nested", wantDecision: "allow"},
		})
	})

	t.Run("test 4 is denied when neither side can be chosen", func(t *testing.T) {
		findings, _ := findingsByName(t, policyTestcasesSBOM, "allow:\n  - Apache-2.0\n  - 0BSD\n")
		assertFindings(t, findings, []expressionCase{
			{pkg: "test-4-nested", wantDecision: "deny", wantLicenses: []string{"MIT", "GPL-2.0-only", "EPL-2.0"}},
		})
	})
}
