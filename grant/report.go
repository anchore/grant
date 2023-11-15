package grant

import (
	"github.com/anchore/grant/cmd/grant/cli/option"
	"github.com/anchore/grant/internal/log"
	"github.com/anchore/syft/syft/pkg"
)

type Report struct {
	// The source of the SBOM
	Source string `json:"source" yaml:"source"`
	// If true, then all licenses are denied by default and only those explicitly allowed are allowed
	Violations map[string][]string `json:"violations" yaml:"violations"`
	// Track packages with licenses that were compliant to the policy
	Compliant map[string][]string `json:"compliant" yaml:"compliant"`
	// ignored is used to track packages with licenses that were not SPDX compliant
	CheckedPackages map[string]bool
	Ignored         map[string][]string `json:"ignored" yaml:"ignored"`
	Config          option.Check        `json:"config" yaml:"config"`
}

func NewReport(src string, cfg option.Check) *Report {
	return &Report{
		Source:          src,
		Violations:      make(map[string][]string),
		Compliant:       make(map[string][]string),
		Ignored:         make(map[string][]string),
		CheckedPackages: make(map[string]bool),
		Config:          cfg,
	}
}

// Check will check the licenses in the given package against the config in the report
func (r *Report) Check(packageName string, licenses pkg.LicenseSet) {
	// track the package as checked
	r.CheckedPackages[packageName] = true

	for _, license := range licenses.ToSlice() {
		if license.SPDXExpression == "" {
			// TODO: we may want to enhance this behavior to allow for a "best guess" SPDX expression
			log.Debugf("package: %s has no SPDX license ID; found possible license: %s", packageName, license.Value)
			r.addIgnored(packageName, license.Value)
			continue
		}
		// check if the license is not allowed
		if !IsAllowed(r.Config, license.SPDXExpression) {
			r.addViolation(packageName, license.SPDXExpression)
			continue
		}
		// otherwise, the license is allowed
		r.addCompliant(packageName, license.SPDXExpression)
	}
	return
}

func (r *Report) addViolation(packageName string, violatingLicenses ...string) {
	if r.Violations == nil {
		r.Violations = make(map[string][]string)
	}

	if licenses, ok := r.Violations[packageName]; ok {
		r.Violations[packageName] = append(licenses, violatingLicenses...)
		return
	}

	r.Violations[packageName] = violatingLicenses
	return
}

func (r *Report) addCompliant(packageName string, compliantLicenses ...string) {
	if r.Compliant == nil {
		r.Compliant = make(map[string][]string)
	}

	if licenses, ok := r.Compliant[packageName]; ok {
		r.Compliant[packageName] = append(licenses, compliantLicenses...)
		return
	}

	r.Compliant[packageName] = compliantLicenses
	return
}

func (r *Report) addIgnored(packageName string, ignoredLicenses ...string) {
	if r.Ignored == nil {
		r.Ignored = make(map[string][]string)
	}

	if licenses, ok := r.Ignored[packageName]; ok {
		r.Ignored[packageName] = append(licenses, ignoredLicenses...)
		return
	}

	r.Ignored[packageName] = ignoredLicenses
	return
}
