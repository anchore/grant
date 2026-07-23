package grant

import (
	"testing"

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
