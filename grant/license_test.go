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

// TestConvertSyftLicenses_SPDXExpressionWithException covers SPDX expressions
// that use the WITH operator. The upstream parser hands these back as a single
// atom ("Apache-2.0 WITH LLVM-exception"), which is not a key in the SPDX
// license list, so grant used to log "unable to get license by ID" and fall back
// to an unresolved license.
func TestConvertSyftLicenses_SPDXExpressionWithException(t *testing.T) {
	tests := []struct {
		expression  string
		wantSPDX    []string
		wantLicense []string
	}{
		{
			expression:  "Apache-2.0 WITH LLVM-exception",
			wantSPDX:    []string{"Apache-2.0 WITH LLVM-exception"},
			wantLicense: []string{"Apache-2.0"},
		},
		{
			expression:  "GPL-2.0-only WITH Classpath-exception-2.0",
			wantSPDX:    []string{"GPL-2.0-only WITH Classpath-exception-2.0"},
			wantLicense: []string{"GPL-2.0-only"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.expression, func(t *testing.T) {
			set := syftPkg.NewLicenseSet(syftPkg.License{Value: tt.expression, SPDXExpression: tt.expression})

			got := ConvertSyftLicenses(set)

			if len(got) != len(tt.wantSPDX) {
				t.Fatalf("expected %d licenses, got %d", len(tt.wantSPDX), len(got))
			}
			for i, want := range tt.wantSPDX {
				if !got[i].IsSPDX() {
					t.Fatalf("expected %q to resolve to an SPDX license, got name %q", tt.expression, got[i].Name)
				}
				if got[i].SPDXExpression != want {
					t.Errorf("got SPDX expression %q, want %q", got[i].SPDXExpression, want)
				}
				if got[i].LicenseID != tt.wantLicense[i] {
					t.Errorf("got license id %q, want %q", got[i].LicenseID, tt.wantLicense[i])
				}
				if got[i].Name == "" {
					t.Errorf("expected the license name to be populated from the SPDX list")
				}
			}
		})
	}
}
