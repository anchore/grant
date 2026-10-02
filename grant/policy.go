package grant

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/github/go-spdx/v2/spdxexp"
	"gopkg.in/yaml.v3"
)

// Policy represents a simplified grant policy that can be decoded from YAML.
//
// Allow and IgnorePackages entries are glob patterns with path.Match syntax on every OS (never filepath.Match,
// so results do not depend on the host): "*" matches within a single "/" segment, a backslash escapes the next character,
// and a malformed pattern never matches. IgnorePackages additionally treats a trailing "/*" as matching any depth
// ("github.com/org/*" matches "github.com/org/a/b").
type Policy struct {
	// Allow is a list of permitted licenses (supports glob patterns)
	Allow []string `yaml:"allow,omitempty"`

	// IgnorePackages is a list of software package name patterns to skip license checking entirely
	// These are package manager package names (npm, Go modules, Debian packages, etc.)
	// Examples: "github.com/anchore/syft", "github.com/anchore/*", "crew", "lite"
	IgnorePackages []string `yaml:"ignore-packages,omitempty"`

	// RequireLicense when true, denies packages with no detected licenses
	RequireLicense bool `yaml:"require-license,omitempty"`

	// RequireKnownLicense when true, denies non-SPDX / unparsable licenses
	RequireKnownLicense bool `yaml:"require-known-license,omitempty"`
}

// IsLicensePermitted checks if a license string matches an allow entry, literally or as a glob. It
// does not apply SPDX expression operators or version ranges, which policy evaluation adds on top.
func (p *Policy) IsLicensePermitted(license string) bool {
	for _, permitted := range p.Allow {
		// Direct match
		if license == permitted {
			return true
		}

		// Convert common regex-style patterns to glob patterns
		pattern := convertRegexToGlob(permitted)

		// glob pattern match (see Policy for the syntax)
		if matched, err := path.Match(pattern, license); err == nil && matched {
			return true
		}
	}

	return false
}

// licenseMatcher answers allow decisions for one evaluation. On top of IsLicensePermitted it applies
// SPDX ranges on the declared side (SPDX 2.3 Annex D.3): a declared "GPL-2.0-or-later" or "GPL-2.0+"
// is allowed by "allow: [GPL-3.0-only]". go-spdx Satisfies does the range comparison, one license at
// a time (see license_expression.go for why it never sees a whole expression). Its v2.7.0 behavior,
// pinned in license_expression_test.go:
//
//   - "-only" is exact: "GPL-2.0-only" is not allowed by "GPL-3.0-only"
//   - ranges stay within one license family: "LGPL-2.0-or-later" is not allowed by "GPL-3.0-only"
//   - a range covers its own base version: "GPL-2.0-or-later" is allowed by "GPL-2.0-only"
//   - deprecated IDs equal their "-only" form both ways: "GPL-2.0" and "GPL-2.0-only"
//   - "X WITH E" is not allowed by an entry for X alone. It needs a literal entry with the same
//     exception, or a glob matching the whole leaf text ("Apache-*" matches "Apache-2.0 WITH
//     LLVM-exception"). Ranges and deprecated IDs still apply with the exception attached:
//     "GPL-2.0-or-later WITH Classpath-exception-2.0" is allowed by "GPL-3.0-only WITH Classpath-exception-2.0"
//   - go-spdx's range table has holes: "GFDL-1.1-invariants-or-later" is not allowed by
//     "GFDL-1.3-invariants-only", and "MPL-1.1+" does not reach "MPL-2.0-no-copyleft-exception"
//   - it also groups some unrelated licenses as versions of one family: "Brian-Gladman-2-Clause+" is
//     allowed by "Brian-Gladman-3-Clause"
//
// Satisfies is only asked about declared licenses whose shape can match something other than
// themselves (see rangeCandidate). Anything else is compared literally, so go-spdx's range table
// never decides a plain ID, and a contradictory "GPL-2.0-only+" stays exact.
//
// Allow entries are only used as range targets when they are literal, canonical SPDX IDs that are
// not ranges themselves. So globs, wrong case ("mit"), and ranges ("GPL-2.0-or-later", "GPL-2.0+",
// with or without an exception) in the allow list keep matching literally, and allowing "GPL-2.0-or-later" never lets a plain
// "GPL-3.0-only" package through.
//
// Not safe for concurrent use.
type licenseMatcher struct {
	policy *Policy
	// targets are the allow entries usable as range targets
	targets []string
	// ranges caches range lookups by declared license (go-spdx rebuilds its range table every call)
	ranges map[string]bool
}

func newLicenseMatcher(policy *Policy) *licenseMatcher {
	m := &licenseMatcher{policy: policy, ranges: make(map[string]bool)}
	for _, permitted := range policy.Allow {
		// a range with an exception attached ("GPL-2.0-or-later WITH E") is still a range
		base, _, _ := strings.Cut(permitted, " WITH ")
		if strings.HasSuffix(base, "+") || strings.HasSuffix(base, "-or-later") {
			continue
		}
		// parsing with go-spdx (not grant's index) keeps the targets to IDs Satisfies accepts, and
		// requiring the canonical spelling keeps case-folding out of the allow list
		if extracted, err := safeExtractLicenses(permitted); err == nil && len(extracted) == 1 && extracted[0] == permitted {
			m.targets = append(m.targets, permitted)
		}
	}
	return m
}

// allowed judges one license on its own
func (m *licenseMatcher) allowed(license License) bool {
	if m.policy.IsLicensePermitted(license.String()) {
		return true
	}
	return license.IsSPDX() && m.inRange(license.SPDXExpression, license.IsDeprecatedLicenseID)
}

// leafAllowed judges one leaf of a declared expression: license is what the leaf flattened into, and
// atom is the normalized SPDX atom, which still carries a "+" range the license dropped
func (m *licenseMatcher) leafAllowed(license License, atom string) bool {
	if m.policy.RequireKnownLicense && !license.IsSPDX() {
		return false
	}
	if m.allowed(license) {
		return true
	}
	// LicenseRefs have no ranges and were already matched literally above
	if atom == "" || strings.Contains(atom, "LicenseRef-") {
		return false
	}
	// the flattened license drops a "+" ("Apache-2.0+" flattens to "Apache-2.0"), so that range is
	// only reachable through the atom
	return (atom != license.String() && m.policy.IsLicensePermitted(atom)) || m.inRange(atom, license.IsDeprecatedLicenseID)
}

// rangeCandidate reports whether a declared license can be allowed by an allow entry other than
// itself: a well formed range ("X+", "X-or-later"), or an ID with a deprecated alias ("GPL-2.0" and
// "GPL-2.0-only" are the same license). A "+" on an ID that already states its range
// ("GPL-2.0-only+") contradicts itself, so it is not a range.
func rangeCandidate(license string, deprecated bool) bool {
	base, _, _ := strings.Cut(license, " WITH ")
	if id, ok := strings.CutSuffix(base, "+"); ok {
		return !strings.HasSuffix(id, "-only") && !strings.HasSuffix(id, "-or-later")
	}
	return deprecated || strings.HasSuffix(base, "-or-later") || strings.HasSuffix(base, "-only")
}

func (m *licenseMatcher) inRange(license string, deprecated bool) bool {
	if len(m.targets) == 0 || !rangeCandidate(license, deprecated) {
		return false
	}
	if satisfied, ok := m.ranges[license]; ok {
		return satisfied
	}
	satisfied := safeSatisfies(license, m.targets)
	m.ranges[license] = satisfied
	return satisfied
}

// safeSatisfies wraps spdxexp.Satisfies the same way safeExtractLicenses wraps parsing: the parser
// panics on some inputs, and any failure must resolve to the stricter answer (not satisfied).
func safeSatisfies(license string, allowed []string) (satisfied bool) {
	defer func() {
		if r := recover(); r != nil {
			satisfied = false
		}
	}()
	satisfied, err := spdxexp.Satisfies(license, allowed)
	return err == nil && satisfied
}

// convertRegexToGlob converts common regex patterns to shell glob patterns
// This allows users to use either regex-style (BSD.*) or glob-style (BSD-*) patterns
func convertRegexToGlob(pattern string) string {
	// Replace .* (regex any) with * (glob any)
	if strings.Contains(pattern, ".*") {
		return strings.ReplaceAll(pattern, ".*", "*")
	}
	// Replace .+ (regex one or more) with * (glob any)
	if strings.Contains(pattern, ".+") {
		return strings.ReplaceAll(pattern, ".+", "*")
	}
	return pattern
}

// IsPackageIgnored checks if a software package should be ignored based on ignore-packages patterns
func (p *Policy) IsPackageIgnored(packageName string) bool {
	for _, pattern := range p.IgnorePackages {
		// Direct match
		if packageName == pattern {
			return true
		}

		// glob pattern match (see Policy for the syntax)
		if matched, err := path.Match(pattern, packageName); err == nil && matched {
			return true
		}

		// Handle patterns like "github.com/mycompany/*"
		if before, ok := strings.CutSuffix(pattern, "/*"); ok {
			prefix := before
			if strings.HasPrefix(packageName, prefix+"/") {
				return true
			}
		}
	}

	return false
}

// isPackageIgnored checks a package against ignore-packages, accepting either its bare name or its
// group-qualified name so a pattern can target one group without affecting the other.
func (p *Policy) isPackageIgnored(pkg Package) bool {
	if p.IsPackageIgnored(pkg.Name) {
		return true
	}

	if qualified := pkg.QualifiedName(); qualified != pkg.Name {
		return p.IsPackageIgnored(qualified)
	}

	return false
}

// LoadPolicy loads a policy from YAML bytes
func LoadPolicy(data []byte) (*Policy, error) {
	var policy Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy: %w", err)
	}
	return &policy, nil
}

// LoadPolicyFromFile loads a policy from a YAML file
func LoadPolicyFromFile(filename string) (*Policy, error) {
	data, err := os.ReadFile(filepath.Clean(filename))
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}
	return LoadPolicy(data)
}
