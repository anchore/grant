package grant

import (
	"github.com/gobwas/glob"
)

// Policy is a structure of rules that define how licenses are denied
type Policy struct {
	Rules Rules
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
func NewPolicy(rules ...Rule) (p Policy, err error) {
	return Policy{
		Rules: rules,
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

		if rule.Glob.Match(license.LicenseID) {
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

//// IsAllowed is a convenience function for library usage of IsDenied negation
//func (p Policy) IsAllowed(license License, pkg *Package) bool {
//	return !p.IsDenied(license, pkg)
//}
