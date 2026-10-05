package grant

import (
	"fmt"
	"strings"

	"github.com/github/go-spdx/v2/spdxexp"

	"github.com/anchore/grant/internal/log"
	"github.com/anchore/grant/internal/spdxlicense"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type LicenseID string

// License is a grant license. SPDXExpression is set when the license resolved
// against the SPDX license list, otherwise Name holds the raw license value.
// Locations are the relative paths for a license that show evidence of its detection.
type License struct {
	ID LicenseID `json:"id"`
	// SPDXExpression is the SPDX expression for the license
	SPDXExpression string `json:"spdxExpression"`
	// Name is the name of the individual license if SPDXExpression is unset
	Name string `json:"name"`
	// Contents are the text of the license
	Contents string `json:"value"`
	// Locations are the paths for a package that show evidence of the license
	Locations []string `json:"location"`

	// These fields (and Name, when SPDXExpression is set) are lifted from the SPDX
	// license list, see internal/spdxlicense/license.go. For an expression with an
	// exception, e.g. "Apache-2.0 WITH LLVM-exception", they describe the base license.
	Reference             string   `json:"reference"`
	IsDeprecatedLicenseID bool     `json:"isDeprecatedLicenseId"`
	DetailsURL            string   `json:"detailsUrl"`
	ReferenceNumber       int      `json:"referenceNumber"`
	LicenseID             string   `json:"licenseId"`
	SeeAlso               []string `json:"seeAlso"`
	IsOsiApproved         bool     `json:"isOsiApproved"`
}

func (l License) String() string {
	if l.SPDXExpression != "" {
		return l.SPDXExpression
	}
	return l.Name
}

func (l License) IsSPDX() bool {
	return l.SPDXExpression != ""
}

// ConvertSyftLicenses converts a syft LicenseSet to a grant License slice
// note: syft licenses can sometimes have complex SPDX expressions.
// Grant these expressions into individual licenses.
// Because license expressions could potentially contain multiple licenses
// that are already represented in the syft license set we need to de-duplicate
// Syft licenses have a "Value" field which is the name of the license
// given to an invalid SPDX expression; grant licenses store this field as "Name"
func ConvertSyftLicenses(set syftPkg.LicenseSet) (licenses []License) {
	licenses, _ = convertSyftLicenses(set)
	return licenses
}

func convertSyftLicenses(set syftPkg.LicenseSet) (licenses []License, declared []licenseTerm) {
	licenses = make([]License, 0)
	checked := make(map[string]bool)
	for _, license := range set.ToSlice() {
		locations := license.Locations.ToSlice()
		licenseLocations := make([]string, 0)
		for _, location := range locations {
			licenseLocations = append(licenseLocations, location.RealPath)
		}

		var term *licenseTerm
		if license.SPDXExpression != "" {
			licenses, term = handleSPDXLicense(license, licenses, licenseLocations, checked)
		} else {
			licenses, term = addNonSPDXLicense(licenses, license, licenseLocations, checked)
		}
		if term != nil {
			declared = append(declared, *term)
		}
	}
	return licenses, declared
}

// safeExtractLicenses wraps spdxexp.ExtractLicenses so a malformed SPDX
// expression cannot take down the whole scan. The upstream parser
// (github.com/github/go-spdx) panics on some inputs, for example an expression
// with a dangling opening parenthesis like "MIT AND (". SBOM license fields
// flow through here unvalidated, so a single malformed value in an SBOM would
// otherwise crash grant. syft guards its own call to this parser for
// the same reason (see anchore/syft#1837); grant does the same here and lets the
// existing error path fall back to treating the value as a non-SPDX license.
func safeExtractLicenses(expression string) (extracted []string, err error) {
	defer func() {
		if r := recover(); r != nil {
			extracted = nil
			err = fmt.Errorf("recovered from panic parsing SPDX expression %q: %v", expression, r)
		}
	}()
	return spdxexp.ExtractLicenses(expression)
}

// handleSPDXLicense flattens one declared SPDX expression into licenses and returns its term tree
// (see license_expression.go). Each leaf refers to the license appended for it (see licenseTerm.key), so
// evaluation always finds the license a leaf refers to.
func handleSPDXLicense(license syftPkg.License, licenses []License, licenseLocations []string, checked map[string]bool) ([]License, *licenseTerm) {
	term, err := parseSPDXDeclaration(license.SPDXExpression)
	if err != nil {
		// the expression itself becomes one non-SPDX license judged on its own (strict). It is named by
		// the expression, not Value: both come from the SBOM, and a Value that disagrees with the
		// expression ("MIT", or a "sha256:" hash that is filtered out) must not stand in for it.
		return addNamedLicense(licenses, license.SPDXExpression, licenseLocations, checked)
	}

	term = mapLeaves(term, func(leaf licenseTerm) licenseTerm {
		var flattened License
		licenses, flattened = addSPDXAtom(licenses, leaf.atom, licenseLocations, checked)
		leaf.member, leaf.spdx = flattened.String(), flattened.IsSPDX()
		return leaf
	})
	return licenses, &term
}

// parseSPDXDeclaration validates an expression with go-spdx, then parses it into a term tree whose
// leaves carry normalized atoms. go-spdx accepting an expression does not mean grant's parser reads it
// the same way ("GPL-3.0+ANDMIT" is two licenses to go-spdx and one id to grant), so the tree is only
// used when its leaves normalize to exactly the licenses go-spdx extracted. Otherwise every extracted
// license is required (AND), which is the strict reading grant used before it honored OR.
func parseSPDXDeclaration(expression string) (licenseTerm, error) {
	atoms, err := safeExtractLicenses(expression)
	if err != nil {
		return licenseTerm{}, err
	}
	term, err := parseLicenseExpression(expression)
	if err == nil {
		term, err = normalizeLeaves(term, atoms)
	}
	if err != nil {
		log.Warnf("unable to read SPDX expression %q as a tree, requiring every license in it: %v", truncate(expression, maxLoggedExpression), err)
		term = licenseTerm{op: opAND}
		for _, atom := range atoms {
			term.terms = append(term.terms, licenseTerm{atom: atom})
		}
	}
	return term, nil
}

// maxLoggedExpression bounds how much of an SBOM supplied expression goes into one log line
const maxLoggedExpression = 200

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// normalizeLeaves normalizes each leaf atom with go-spdx, and fails unless the leaves cover exactly the
// licenses go-spdx extracted from the whole expression
func normalizeLeaves(term licenseTerm, atoms []string) (licenseTerm, error) {
	want := make(map[string]bool, len(atoms))
	for _, atom := range atoms {
		want[atom] = true
	}
	got := make(map[string]bool, len(atoms))
	var leafErr error
	term = mapLeaves(term, func(leaf licenseTerm) licenseTerm {
		extracted, err := safeExtractLicenses(leaf.atom)
		if err != nil || len(extracted) != 1 || !want[extracted[0]] {
			leafErr = fmt.Errorf("license %q does not match what go-spdx extracted from the expression", leaf.atom)
			return leaf
		}
		leaf.atom = extracted[0]
		got[leaf.atom] = true
		return leaf
	})
	if leafErr != nil {
		return licenseTerm{}, leafErr
	}
	if len(got) != len(want) {
		return licenseTerm{}, fmt.Errorf("expression has %d licenses, go-spdx extracted %d", len(got), len(want))
	}
	return term, nil
}

func mapLeaves(t licenseTerm, fn func(licenseTerm) licenseTerm) licenseTerm {
	if t.op == "" {
		return fn(t)
	}
	terms := make([]licenseTerm, 0, len(t.terms))
	for _, term := range t.terms {
		terms = append(terms, mapLeaves(term, fn))
	}
	t.terms = terms
	return t
}

// addSPDXAtom adds the license for one normalized atom unless an identical one was already added,
// and returns the license the atom refers to either way
func addSPDXAtom(licenses []License, atom string, licenseLocations []string, checked map[string]bool) ([]License, License) {
	id := strings.TrimRight(atom, "+")

	// we have what seems to be a valid SPDX license ID, let's try and get more info about it
	spdxLicense, err := spdxlicense.GetLicenseByID(id)
	if err != nil {
		// not on the SPDX list (LicenseRef-*, "X WITH E"), so it is kept under its own atom text.
		// TODO: best matching against the spdx list index
		unknown := License{Name: atom, Locations: licenseLocations}
		if !check(checked, unknown.key()) {
			log.Debugf("unable to get license by ID: %s; no matching spdx id found", id)
			licenses = append(licenses, unknown)
		}
		return licenses, unknown
	}

	known := License{
		SPDXExpression:        id,
		Name:                  spdxLicense.Name,
		Locations:             licenseLocations,
		Reference:             spdxLicense.Reference,
		IsDeprecatedLicenseID: spdxLicense.IsDeprecatedLicenseID,
		DetailsURL:            spdxLicense.DetailsURL,
		ReferenceNumber:       spdxLicense.ReferenceNumber,
		LicenseID:             spdxLicense.LicenseID,
		SeeAlso:               spdxLicense.SeeAlso,
		IsOsiApproved:         spdxLicense.IsOsiApproved,
	}
	// prevent duplicates from being added when using SPDX expressions
	// EG: "MIT AND MIT" is valid, but we want to de-duplicate these
	if !check(checked, known.key()) {
		licenses = append(licenses, known)
	}
	return licenses, known
}

// addNonSPDXLicense adds a license declared by name and returns it as a single leaf declaration
func addNonSPDXLicense(licenses []License, license syftPkg.License, locations []string, checked map[string]bool) ([]License, *licenseTerm) {
	// Filter out sha256: licenses - these are content hashes from Syft when license detection fails
	if strings.HasPrefix(license.Value, "sha256:") {
		return licenses, nil
	}

	return addNamedLicense(licenses, license.Value, locations, checked)
}

// addNamedLicense adds a non-SPDX license by name and returns it as a single leaf declaration
func addNamedLicense(licenses []License, name string, locations []string, checked map[string]bool) ([]License, *licenseTerm) {
	named := License{
		Name:      name,
		Locations: locations,
	}
	if !check(checked, named.key()) {
		licenses = append(licenses, named)
	}
	return licenses, &licenseTerm{member: named.String()}
}

func check(checked map[string]bool, license string) bool {
	if _, ok := checked[license]; !ok {
		checked[license] = true
		return false
	}
	return true
}
