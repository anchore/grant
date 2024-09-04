package grant

import (
	"strings"

	"github.com/gobwas/glob"
)

// Policy is a structure of rules that define how licenses are denied
// TODO: maybe there should be a strict option that denies all and then only allows what is explicitly allowed
type Policy struct {
	Rules        Rules
	MatchNonSPDX bool
}

var DefaultDenyAll = Rule{
	Name:       "default-deny-all",
	Glob:       glob.MustCompile("*"),
	Exceptions: []glob.Glob{},
	Mode:       Deny,
	Reason:     "grant by default will deny all licenses",
}

// DefaultPolicy returns a policy that denies all licenses
func DefaultPolicy() Policy {
	return Policy{
		Rules: []Rule{DefaultDenyAll},
	}
}

// NewPolicy builds a policy from lists of allow, deny, and ignore glob patterns
// It lower cases all patterns to make matching against the spdx license set case-insensitive
func NewPolicy(matchNonSPDX bool, rules ...Rule) (p Policy, err error) {
	if len(rules) == 0 {
		return Policy{
			Rules:        Rules{DefaultDenyAll},
			MatchNonSPDX: matchNonSPDX,
		}, nil
	}
	return Policy{
		Rules:        rules,
		MatchNonSPDX: matchNonSPDX,
	}, nil
}

// IsEmpty returns true if the policy has no allow or deny licenses
func (p Policy) IsEmpty() bool {
	return len(p.Rules) == 0
}

// IsDenied returns true if the given license is denied by the policy
func (p Policy) IsDenied(license License, pkg *Package) (bool, *Rule) {
	for _, rule := range p.Rules {
		var toMatch string

		if license.IsSPDX() {
			toMatch = strings.ToLower(license.LicenseID)
		} else {
			toMatch = strings.ToLower(license.Name)
		}

		toMatch = strings.ToLower(toMatch)
		// TODO: write tests for this section
		if rule.Glob.Match(toMatch) && toMatch != "" {
			if pkg == nil {
				return true, &rule
			}
			for _, exception := range rule.Exceptions {
				if exception.Match(pkg.Name) {
					return rule.Mode != Deny, &rule
				}
			}
			// true when Mode=Deny, false otherwise
			return rule.Mode == Deny, &rule
		}
	}
	return false, nil
}
