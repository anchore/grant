package grant

import (
	"strings"

	"github.com/github/go-spdx/v2/spdxexp"

	"github.com/anchore/grant/cmd/grant/cli/option"
	"github.com/anchore/grant/internal/log"
)

type Report struct {
	// The source of the report
	Source string `json:"source" yaml:"source"`
	// Track packages and their licenses that violated the policy
	PackageViolations map[string][]string `json:"violations" yaml:"violations"`
	// Track packages with licenses that were compliant to the policy
	PackageCompliant map[string][]string `json:"compliant" yaml:"compliant"`
	// ignored is used to track packages with licenses that were not SPDX compliant
	PackageIgnored  map[string][]string `json:"ignored" yaml:"ignored"`
	CheckedPackages map[string]struct{}

	// Track licenses that were not allowed by the policy and the packages that contained them
	LicenseViolations map[string][]string `json:"license_violations" yaml:"license_violations"`
	// Track licenses that were allowed by the policy and the packages that contained them
	LicenseCompliant map[string][]string `json:"license_compliant" yaml:"license_compliant"`
	// Track licenses that were not SPDX compliant and the packages that contained them
	LicenseIgnored map[string][]string `json:"license_ignored" yaml:"license_ignored"`
	// Track list of licenses that were checked for the above two maps
	CheckedLicenses map[string]struct{}
	Config          option.Check `json:"config" yaml:"config"`
}

func NewReport(src string, cfg option.Check) *Report {
	// lowercase all the licenses in the config for case-insensitive matching
	for i, lic := range cfg.AllowLicenses {
		cfg.AllowLicenses[i] = strings.ToLower(lic)
	}

	for i, lic := range cfg.DenyLicenses {
		cfg.DenyLicenses[i] = strings.ToLower(lic)
	}
	return &Report{
		Source:            src,
		PackageViolations: make(map[string][]string),
		PackageCompliant:  make(map[string][]string),
		PackageIgnored:    make(map[string][]string),
		CheckedPackages:   make(map[string]struct{}),
		LicenseViolations: make(map[string][]string),
		LicenseCompliant:  make(map[string][]string),
		LicenseIgnored:    make(map[string][]string),
		CheckedLicenses:   make(map[string]struct{}),
		Config:            cfg,
	}
}

// Check will check the licenses in the given package against the config in the report
func (r *Report) Check(packageName string, licenses []License) {
	// track the package as checked
	r.CheckedPackages[packageName] = struct{}{}

	for _, license := range licenses {
		if license.SPDXExpression == "" {
			// TODO: we may want to enhance this behavior to allow for a "best guess" SPDX expression
			log.Debugf("package: %s has a license with no SPDX license ID; found possible license: %s", packageName, license.Value)
			r.addIgnored(packageName, license.Value)
			continue
		}

		// if there is an SPDX expression, extract the licenses and break them into their own License objects
		// note: we still treat expressions with OR as a potential violation that users would need to manually review
		// TODO: grant command that will "fix" the SPDX expression to be a single license (letting the author chose)
		// this should modify the config file in some way that the user can review and commit
		licenses, err := spdxexp.ExtractLicenses(license.SPDXExpression)
		if err != nil {
			log.Debugf("package: %s has a license with an invalid SPDX license ID: %s", packageName, license.SPDXExpression)
			r.addIgnored(packageName, license.SPDXExpression)
			continue
		}

		for _, lic := range licenses {
			// check if the license is denied
			if !IsAllowed(r.Config, lic) {
				r.addViolation(packageName, lic)
				continue
			}
			// otherwise, the license is allowed
			r.addCompliant(packageName, lic)
		}
	}
	return
}

func (r *Report) addViolation(packageName string, violatingLicenses ...string) {
	for _, violatingLicense := range violatingLicenses {
		r.LicenseViolations[violatingLicense] = append(r.LicenseViolations[violatingLicense], packageName)
	}

	r.PackageViolations[packageName] = append(r.PackageViolations[packageName], violatingLicenses...)
}

func (r *Report) addCompliant(packageName string, compliantLicenses ...string) {
	for _, compliantLicense := range compliantLicenses {
		r.LicenseCompliant[compliantLicense] = append(r.LicenseCompliant[compliantLicense], packageName)
	}

	r.PackageCompliant[packageName] = append(r.PackageCompliant[packageName], compliantLicenses...)
}

func (r *Report) addIgnored(packageName string, ignoredLicenses ...string) {
	for _, ignoredLicense := range ignoredLicenses {
		r.LicenseIgnored[ignoredLicense] = append(r.LicenseIgnored[ignoredLicense], packageName)
	}

	r.PackageIgnored[packageName] = append(r.PackageIgnored[packageName], ignoredLicenses...)
}
