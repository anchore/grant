package grant

import (
	"fmt"
	"strings"
)

// SPDX license expressions (SPDX 2.3 Annex D)
//
// syft hands grant each declared license as an SPDX expression. grant flattens it into individual
// licenses for reporting, and keeps the declaration as a licenseTerm tree so a policy can apply the
// operators:
//
//   - OR is a choice (D.4.2): the expression passes when any side passes
//   - AND requires every side (D.4.3)
//   - WITH attaches an exception to one license (D.4.4). "X WITH E" is a single leaf, so allowing X
//     alone never satisfies it
//   - precedence is "+", then WITH, then AND, then OR (D.4.5), and parentheses override it
//   - "+" and "-or-later" mean that version or any later one (D.3), see licenseMatcher
//
// Separate declarations on one package (separate syft License entries) are separate trees, and every
// tree must pass, so they AND together.
//
// go-spdx (spdxexp.ExtractLicenses) validates and normalizes the expression before this parser
// runs, so the parser only has to handle the grammar go-spdx already accepted. The two can still
// disagree: go-spdx reads operators by prefix ("MIT ORApache-2.0") and ends an ID at "+"
// ("GPL-3.0+ANDMIT"), where grant's parser rejects the first and reads the second as one ID. So a tree
// is only kept when its leaves normalize to exactly the licenses go-spdx extracted (see
// parseSPDXDeclaration), and any disagreement, or nesting past maxExpressionDepth, falls back to
// requiring every license (AND). Boolean evaluation is
// done here, on purpose: go-spdx v2.7.0 spdxexp.Satisfies is not sound on nested input. It drops an
// OR made only of LicenseRefs when that OR sits under an AND, it can alias slices while expanding
// nested ANDs and return true when a required license is not allowed, and it expands AND-of-ORs into
// every combination (exponential). grant only asks Satisfies about one leaf at a time, where none of
// that applies.
//
// go-spdx v2.7.0 behavior this relies on, each case pinned in license_expression_test.go so swapping
// the SPDX implementation shows up as test failures:
//
//   - operators are case sensitive. "MIT and Apache-2.0" is a parse error (SPDX 2.3 agrees, SPDX 3.0
//     also allows all-lowercase operators)
//   - license IDs and exceptions are case insensitive and normalized ("mit" becomes "MIT")
//   - only spaces separate tokens. A tab or newline is a parse error
//   - "+" must touch its ID ("GPL-2.0 +" is an error). "GPL-2.0+" normalizes to "GPL-2.0-or-later",
//     and an ID with no "-or-later" form keeps its plus ("Apache-2.0+")
//   - "LicenseRef-x+" is an error. "LicenseRef-x WITH E" is an error too, though the SPDX 2.3 grammar
//     allows it. "DocumentRef-a : LicenseRef-b" normalizes to "DocumentRef-a:LicenseRef-b"
//   - SPDX 3.0 "AdditionRef-" exceptions, NONE and NOASSERTION are parse errors
//   - some IDs that are not on the SPDX list are accepted and rewritten: "MIT-only" becomes "MIT",
//     "Apache-2.0-or-later" becomes "Apache-2.0+", and "MIT+" is kept as is
//   - an "X WITH E" leaf flattens to an SPDX license described by X (see spdxlicense.GetLicenseByID),
//     so it is known under require-known-license. "X+ WITH E" is unknown when X has no "-or-later"
//     form, since the index has no "X+"
//   - parentheses may touch operators ("MIT OR(Apache-2.0)") but not IDs ("MIT(Apache-2.0)" is an
//     error), and a WITH cannot follow a parenthesized group
//   - parsing can panic on some malformed input (see safeExtractLicenses)
//
// Anything that fails to parse is kept as one non-SPDX license under the declared value and judged
// on its own, which is the strict reading.

// maxExpressionDepth caps parenthesis nesting. go-spdx accepts nesting deep enough to overflow the
// stack of the recursive parser below (an unrecoverable crash), and real expressions nest a few levels
// at most. Deeper input fails to parse, which falls back to requiring every license.
const maxExpressionDepth = 100

const (
	opAND  = "AND"
	opOR   = "OR"
	opWITH = "WITH"
)

// licenseTerm is one node of a declared license expression
type licenseTerm struct {
	// op is opAND or opOR for an operator node, and empty for a leaf
	op    string
	terms []licenseTerm

	// member is the License.String() of the flattened license this leaf refers to (leaf only), and
	// spdx is its IsSPDX(). Both are needed to find it: a non-SPDX "MIT" is not the SPDX MIT.
	member string
	spdx   bool
	// atom is the normalized SPDX atom the leaf was parsed from. It keeps a "+" range that the
	// flattened license drops ("Apache-2.0+" flattens to "Apache-2.0"). Empty for non-SPDX leaves.
	atom string
}

// key identifies the license a leaf refers to, see licenseKey
func (t licenseTerm) key() string {
	return licenseKey(t.member, t.spdx)
}

// licenseKey identifies a flattened license within a package. A license declared by name is kept
// apart from an SPDX license spelled the same, so require-known-license cannot be passed by naming one.
func licenseKey(id string, spdx bool) string {
	if spdx {
		return "spdx:" + id
	}
	return "name:" + id
}

func (l License) key() string {
	return licenseKey(l.String(), l.IsSPDX())
}

// satisfied evaluates the term with leafAllowed deciding each leaf
func (t licenseTerm) satisfied(leafAllowed func(licenseTerm) bool) bool {
	switch t.op {
	case opAND:
		for _, term := range t.terms {
			if !term.satisfied(leafAllowed) {
				return false
			}
		}
		return true
	case opOR:
		for _, term := range t.terms {
			if term.satisfied(leafAllowed) {
				return true
			}
		}
		return false
	default:
		return leafAllowed(t)
	}
}

// failedLeaves calls fn for every leaf that keeps the term from passing. Under a failed AND only the
// operands that failed are walked, so an OR that already passed is not blamed for the failure.
func (t licenseTerm) failedLeaves(leafAllowed func(licenseTerm) bool, fn func(licenseTerm)) {
	switch t.op {
	case opAND, opOR:
		for _, term := range t.terms {
			if !term.satisfied(leafAllowed) {
				term.failedLeaves(leafAllowed, fn)
			}
		}
	default:
		if !leafAllowed(t) {
			fn(t)
		}
	}
}

// leaves calls fn for every leaf of the term
func (t licenseTerm) leaves(fn func(licenseTerm)) {
	if t.op == "" {
		fn(t)
		return
	}
	for _, term := range t.terms {
		term.leaves(fn)
	}
}

// parseLicenseExpression parses an expression go-spdx has already accepted into a tree whose leaves
// carry their atom text ("MIT", "GPL-2.0+ WITH Classpath-exception-2.0", "DocumentRef-a:LicenseRef-b").
// Leaf atoms are not normalized here and member is unset, the caller fills both in.
func parseLicenseExpression(expression string) (licenseTerm, error) {
	p := &expressionParser{tokens: tokenizeLicenseExpression(expression)}
	term, err := p.or()
	if err != nil {
		return licenseTerm{}, err
	}
	if p.pos != len(p.tokens) {
		return licenseTerm{}, fmt.Errorf("unexpected token %q", truncate(p.tokens[p.pos], maxLoggedExpression))
	}
	return term, nil
}

// tokenizeLicenseExpression splits on spaces (the only separator go-spdx accepts) and around
// parentheses and the DocumentRef ":" (which go-spdx allows to be spaced)
func tokenizeLicenseExpression(expression string) []string {
	var tokens []string
	var current strings.Builder
	flush := func() {
		if current.Len() > 0 {
			tokens = append(tokens, current.String())
			current.Reset()
		}
	}
	for _, r := range expression {
		switch r {
		case ' ':
			flush()
		case '(', ')', ':':
			flush()
			tokens = append(tokens, string(r))
		default:
			current.WriteRune(r)
		}
	}
	flush()
	return tokens
}

type expressionParser struct {
	tokens []string
	pos    int
	depth  int
}

func (p *expressionParser) peek() string {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos]
	}
	return ""
}

func (p *expressionParser) next() string {
	token := p.peek()
	p.pos++
	return token
}

// or := and ("OR" and)*
func (p *expressionParser) or() (licenseTerm, error) {
	return p.binary(opOR, p.and)
}

// and := primary ("AND" primary)*
func (p *expressionParser) and() (licenseTerm, error) {
	return p.binary(opAND, p.primary)
}

func (p *expressionParser) binary(op string, operand func() (licenseTerm, error)) (licenseTerm, error) {
	first, err := operand()
	if err != nil {
		return licenseTerm{}, err
	}
	terms := []licenseTerm{first}
	for p.peek() == op {
		p.next()
		term, err := operand()
		if err != nil {
			return licenseTerm{}, err
		}
		terms = append(terms, term)
	}
	if len(terms) == 1 {
		return first, nil
	}
	return licenseTerm{op: op, terms: terms}, nil
}

// primary := "(" or ")" | id [":" id] ["WITH" id]
func (p *expressionParser) primary() (licenseTerm, error) {
	if p.peek() == "(" {
		p.next()
		if p.depth++; p.depth > maxExpressionDepth {
			return licenseTerm{}, fmt.Errorf("license expression is nested deeper than %d", maxExpressionDepth)
		}
		term, err := p.or()
		p.depth--
		if err != nil {
			return licenseTerm{}, err
		}
		if p.next() != ")" {
			return licenseTerm{}, fmt.Errorf("missing closing parenthesis")
		}
		return term, nil
	}

	atom, err := p.id()
	if err != nil {
		return licenseTerm{}, err
	}
	if p.peek() == ":" {
		p.next()
		ref, err := p.id()
		if err != nil {
			return licenseTerm{}, err
		}
		atom += ":" + ref
	}
	if p.peek() == opWITH {
		p.next()
		exception, err := p.id()
		if err != nil {
			return licenseTerm{}, err
		}
		atom += " WITH " + exception
	}
	return licenseTerm{atom: atom}, nil
}

func (p *expressionParser) id() (string, error) {
	switch token := p.next(); token {
	case "", "(", ")", ":", opAND, opOR, opWITH:
		return "", fmt.Errorf("expected a license id, found %q", token)
	default:
		return token, nil
	}
}
