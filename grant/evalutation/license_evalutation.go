package evalutation

import (
	"github.com/anchore/grant/grant"
	"github.com/anchore/syft/syft/sbom"
)

func NewLicenseEvaluations(ec EvaluationConfig, c grant.Case) LicenseEvaluations {
	evaluations := make([]LicenseEvaluation, 0)
	for _, sb := range c.SBOMS {
		evaluations = checkSBOM(ec, c, sb, evaluations)
	}

	for _, l := range c.Licenses {
		evaluations = checkLicense(ec, nil, l, evaluations)
	}

	return evaluations
}

func checkSBOM(ec EvaluationConfig, c grant.Case, sb sbom.SBOM, evaluations []LicenseEvaluation) []LicenseEvaluation {
	for pkg := range sb.Artifacts.Packages.Enumerate() {
		// since we use syft as a library to generate the sbom we need to convert its packages/licenses to grant types
		grantPkg := convertSyftPackage(pkg)
		if len(grantPkg.Licenses) == 0 {
			le := NewLicenseEvaluation(grant.License{}, grantPkg, ec.Policy, []Reason{ReasonNoLicenseFound}, true)
			evaluations = append(evaluations, le)
			continue
		}

		for _, l := range grantPkg.Licenses {
			evaluations = checkLicense(ec, grantPkg, l, evaluations)
		}
	}
	return evaluations
}

func checkLicense(ec EvaluationConfig, pkg *grant.Package, l grant.License, evaluations []LicenseEvaluation) []LicenseEvaluation {
	if !l.IsSPDX() {
		// TODO: check if the config wants us to check for non-SPDX licenses
	}
	if ec.Policy.IsDenied(l) {
		le := NewLicenseEvaluation(l, pkg, ec.Policy, []Reason{ReasonLicenseDenied}, false)
		return append(evaluations, le)
	}
	le := NewLicenseEvaluation(l, pkg, ec.Policy, []Reason{ReasonLicenseAllowed}, true)
	return append(evaluations, le)
}

type LicenseEvaluations []LicenseEvaluation

func (le LicenseEvaluations) Packages() []grant.Package {
	packages := make([]grant.Package, 0)
	// get the set of unique packages from the list...
	for _, e := range le {
		if e.Package != nil {
			packages = append(packages, *e.Package)
		}
	}
	return packages
}

func (le LicenseEvaluations) Licenses() []grant.License {
	licenses := make([]grant.License, 0)
	licenseMap := make(map[string]struct{})
	// get the set of unique licenses from the list...
	for _, e := range le {
		if _, ok := licenseMap[e.License.LicenseID]; !ok {
			licenseMap[e.License.LicenseID] = struct{}{}
			licenses = append(licenses, e.License)
		}
	}
	return licenses
}

func (le LicenseEvaluations) FailedLicenses() []grant.License {
	licenses := make([]grant.License, 0)
	licenseMap := make(map[string]struct{})
	// get the set of unique licenses from the list...
	for _, e := range le {
		if !e.Pass {
			if _, ok := licenseMap[e.License.LicenseID]; !ok && e.License.LicenseID != "" {
				licenseMap[e.License.LicenseID] = struct{}{}
				licenses = append(licenses, e.License)
			}
		}
	}
	return licenses
}

func (le LicenseEvaluations) IsFailed() bool {
	for _, e := range le {
		if !e.Pass {
			return true
		}
	}
	return false
}

type LicenseEvaluation struct {
	// inputs into evaluation...
	License grant.License  // the license that we evaluated
	Package *grant.Package // any artifact license is evaluated with

	// what's used to evaluate...
	Policy grant.Policy // what the determination was made against

	// the output of an evaluation...
	Reason []Reason // reasons that the evaluation value the way it is
	Pass   bool     // The final evaluation
}

func NewLicenseEvaluation(license grant.License, pkg *grant.Package, policy grant.Policy, reasons []Reason, pass bool) LicenseEvaluation {
	return LicenseEvaluation{
		License: license,
		Package: pkg,
		Policy:  policy,
		Reason:  reasons,
		Pass:    pass,
	}
}
