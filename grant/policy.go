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

// DefaultPolicy returns a policy that denies all licenses
func DefaultPolicy() Policy {
	return Policy{
		Rules: []Rule{
			{
				Glob:       glob.MustCompile("*"),
				Exceptions: []glob.Glob{},
				Mode:       Deny,
				Reason:     "grant by default will deny all licenses",
			},
		},
	}
}

// NewPolicy builds a policy from lists of allow, deny, and ignore glob patterns
// It lower cases all patterns to make matching against the spdx license set case-insensitive
func NewPolicy(matchNonSPDX bool, rules ...Rule) (p Policy, err error) {
	return Policy{
		Rules:        rules,
		MatchNonSPDX: matchNonSPDX,
	}, nil
}

// IsEmpty returns true if the policy has no allow or deny licenses
func (p Policy) IsEmpty() bool {
	if len(p.Rules) == 0 {
		return true
	}
	return false
}

// IsDenied returns true if the given license is denied by the policy
func (p Policy) IsDenied(license License, pkg *Package) (bool, *Rule) {
	for _, rule := range p.Rules {
		if rule.Mode != Deny {
			continue
		}

		var toMatch string
		if license.IsSPDX() {
			toMatch = strings.ToLower(license.LicenseID)
		}
		if p.MatchNonSPDX && !license.IsSPDX() {
			toMatch = strings.ToLower(license.Name)
		}

		toMatch = strings.ToLower(license.Name)
		if rule.Glob.Match(toMatch) && toMatch != "" {
			if pkg == nil {
				return true, &rule
			}
			for _, exception := range rule.Exceptions {
				if exception.Match(pkg.Name) {
					return false, &rule
				}
			}
			return true, &rule
		}
	}
	return false, nil
}
