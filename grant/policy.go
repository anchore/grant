package grant

import (
	"strings"

	"github.com/gobwas/glob"
)

// Policy is a structure of glob patterns that represent either allowed or denied licenses
type Policy struct {
	AllowLicenses []glob.Glob `json:"allowLicenses" yaml:"allowLicenses" mapstructure:"allowLicenses"`
	DenyLicenses  []glob.Glob `json:"denyLicenses" yaml:"denyLicenses" mapstructure:"denyLicenses"`
	denyAll       bool
	allowAll      bool
}

// DefaultPolicy returns a policy that denies all licenses
func DefaultPolicy() *Policy {
	return &Policy{
		AllowLicenses: make([]glob.Glob, 0),
		DenyLicenses: []glob.Glob{
			glob.MustCompile("*"),
		},
		denyAll: true,
	}
}

// NewPolicy builds a policy from lists of allow and deny glob patterns
// It lower cases all patterns to make matching against the spdx license set case-insensitive
// The grant.Result.Evaluate() function found under grant/result.go will lower case all licenses for matching
func NewPolicy(allowLicenses []string, denyLicenses []string) (*Policy, error) {
	if len(allowLicenses) == 0 && len(denyLicenses) == 0 {
		return DefaultPolicy(), nil
	}

	var (
		denyAll  bool
		allowAll bool
	)

	denyGlobs := make([]glob.Glob, 0)
	for _, deny := range denyLicenses {
		deny = strings.ToLower(deny)
		denyGlob, err := glob.Compile(deny)
		if err != nil {
			return nil, err
		}
		denyGlobs = append(denyGlobs, denyGlob)
		if deny == "*" {
			denyAll = true
		}
	}

	allowGlobs := make([]glob.Glob, 0)
	for _, allow := range allowLicenses {
		allow = strings.ToLower(allow)
		allowGlob, err := glob.Compile(allow)
		if err != nil {
			return nil, err
		}
		allowGlobs = append(allowGlobs, allowGlob)
		if allow == "*" {
			allowAll = true
		}
	}

	return &Policy{
		AllowLicenses: allowGlobs,
		DenyLicenses:  denyGlobs,
		denyAll:       denyAll,
		allowAll:      allowAll,
	}, nil
}

// IsEmpty returns true if the policy has no allow or deny licenses
func (p Policy) IsEmpty() bool {
	return len(p.AllowLicenses) == 0 && len(p.DenyLicenses) == 0
}

// Deny returns true if the given license is denied by the policy
// If the policy has a "*" deny all, then the allow list is checked first
// If the policy has no "*" deny all, then the deny list is checked first
// If the license is not denied by the policy, but deny all is not set, then the allow list is checked
func (p Policy) Deny(license License) bool {
	// deny is superior to allow
	if p.denyAll && p.allowAll {
		return true
	}
	// if the policy had "*" in the deny list then deny all is set on policy creation
	if p.denyAll {
		for _, allow := range p.AllowLicenses {
			if allow.Match(license.String()) {
				return false
			}
		}
		return true
	}

	// if the policy had "*" in the allow list then allow all is set on policy creation
	if p.allowAll {
		for _, deny := range p.DenyLicenses {
			if deny.Match(license.String()) {
				return true
			}
		}
		return false
	}

	// otherwise, check the deny list for explicit denies
	for _, deny := range p.DenyLicenses {
		if deny.Match(license.String()) {
			return true
		}
	}

	// check the allow list for explicit allows
	for _, allow := range p.AllowLicenses {
		if allow.Match(license.String()) {
			return false
		}
	}

	// if the license is not explicitly denied, and deny all is not set, and allow all is not set, and
	// the licenses is not explicitly allowed, it is denied by default
	return false
}

// Allow is a convenience function for library consumers
func (p Policy) Allow(license License) bool {
	return !p.Deny(license)
}
