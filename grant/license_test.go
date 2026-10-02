package grant

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grant/internal/spdxlicense"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// TestConvertSyftLicenses_MalformedSPDXExpressionDoesNotPanic feeds a license
// whose SPDXExpression is a malformed expression with a dangling opening
// parenthesis. This is the shape that reaches handleSPDXLicense when grant
// decodes an SBOM whose license field is malformed. The upstream SPDX parser
// panics on this input, so without the guard in handleSPDXLicense the whole scan
// would crash. The expression should instead fall back to a non-SPDX license.
func TestConvertSyftLicenses_MalformedSPDXExpressionDoesNotPanic(t *testing.T) {
	malformed := []string{
		"MIT AND (",
		"(",
		"(((((",
		"MIT OR (",
	}

	for _, expr := range malformed {
		expr := expr
		t.Run(expr, func(t *testing.T) {
			set := syftPkg.NewLicenseSet(syftPkg.License{Value: expr, SPDXExpression: expr})

			// must not panic
			got := ConvertSyftLicenses(set)

			if len(got) != 1 {
				t.Fatalf("expected 1 license, got %d", len(got))
			}
			// the malformed expression should be carried as a plain name, not
			// treated as a valid SPDX expression
			if got[0].IsSPDX() {
				t.Fatalf("expected malformed expression %q to fall back to a non-SPDX license, got SPDX license %q", expr, got[0].SPDXExpression)
			}
			if got[0].Name != expr {
				t.Fatalf("expected fallback license name %q, got %q", expr, got[0].Name)
			}
		})
	}
}

// TestConvertSyftLicenses_SPDXExpressionWithException covers SPDX expressions
// that use the WITH operator (see #500). The upstream parser hands these back as
// a single atom ("Apache-2.0 WITH LLVM-exception"), which is not a key in the SPDX
// license list. This asserts at the response layer, where the risk column that
// read "Unknown" in the issue is derived, and pins the resulting policy decisions.
func TestConvertSyftLicenses_SPDXExpressionWithException(t *testing.T) {
	tests := []struct {
		expression string
		wantSPDX   []string
		wantRisk   spdxlicense.RiskCategory
	}{
		{
			expression: "Apache-2.0 OR Apache-2.0 WITH LLVM-exception OR MIT",
			wantSPDX:   []string{"Apache-2.0", "Apache-2.0 WITH LLVM-exception", "MIT"},
			wantRisk:   spdxlicense.RiskCategoryLow,
		},
		{
			// the exception does not lower the risk of the license it applies to
			expression: "GPL-2.0-only WITH Classpath-exception-2.0",
			wantSPDX:   []string{"GPL-2.0-only WITH Classpath-exception-2.0"},
			wantRisk:   spdxlicense.RiskCategoryHigh,
		},
	}

	for _, tt := range tests {
		t.Run(tt.expression, func(t *testing.T) {
			set := syftPkg.NewLicenseSet(syftPkg.License{Value: tt.expression, SPDXExpression: tt.expression})
			pkg := Package{Name: "pkg", Licenses: ConvertSyftLicenses(set)}

			var got []string
			for _, l := range pkg.Licenses {
				assert.True(t, l.IsSPDX(), "%q should resolve to an SPDX license", l.String())
				got = append(got, l.String())
			}
			assert.ElementsMatch(t, tt.wantSPDX, got)

			finding := packageToFinding(pkg, DecisionAllow)
			for _, d := range finding.Licenses {
				assert.NotEmpty(t, d.RiskCategory, "%q should have a risk category", d.ID)
				assert.NotEmpty(t, d.Reference, "%q should have a reference", d.ID)
				if strings.Contains(d.ID, " WITH ") {
					assert.Equal(t, tt.wantRisk, d.RiskCategory, "%q risk", d.ID)
				}
			}
		})
	}

	// policy matching still sees the full expression: an exact allow of the base
	// license does not cover its exception form, a glob does, and the exception form
	// counts as a known license
	pkg := Package{Name: "pkg", Licenses: ConvertSyftLicenses(syftPkg.NewLicenseSet(syftPkg.License{
		Value:          "MIT WITH Classpath-exception-2.0",
		SPDXExpression: "MIT WITH Classpath-exception-2.0",
	}))}
	c := &Case{}
	assert.Len(t, c.evaluatePackage(&pkg, &Policy{Allow: []string{"MIT"}, RequireKnownLicense: true}).DeniedLicenses, 1)
	assert.Equal(t, "all licenses allowed", c.evaluatePackage(&pkg, &Policy{Allow: []string{"MIT*"}, RequireKnownLicense: true}).Reason)
}
