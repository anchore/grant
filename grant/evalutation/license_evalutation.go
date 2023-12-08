package evalutation

import (
	"github.com/anchore/grant/grant"
)

func NewLicenseEvaluations(ec EvaluationConfig, c grant.Case) LicenseEvaluations {
	evaluations := make([]LicenseEvaluation, 0)
	// TODO: probably want to use some concurrency here
	for _, sb := range c.SBOMS {
		for pkg := range sb.Artifacts.Packages.Enumerate() {
			grantPkg := convertSyftPackage(pkg)
			// since we use syft as a library to generate the sbom we need to convert its packages/licenses to grant types
			if len(grantPkg.Licenses) == 0 {
				evaluations = append(evaluations, LicenseEvaluation{
					License: grant.License{},
					Package: grantPkg,
					Policy:  ec.Policy,
					Reason:  []Reason{ReasonNoLicenseFound},
					Pass:    true,
				})
				continue
			}

			for _, l := range grantPkg.Licenses {
				if !l.IsSPDX() {
					// TODO: check if the config wants us to check for non-SPDX licenses
				}
				if ec.Policy.IsDenied(l) {
					evaluations = append(evaluations, LicenseEvaluation{
						License: l,
						Package: grantPkg,
						Policy:  ec.Policy,
						Reason:  []Reason{ReasonLicenseDenied},
						Pass:    false,
					})
					continue
				}
				// otherwise, the license is allowed
				evaluations = append(evaluations, LicenseEvaluation{
					License: l,
					Package: grantPkg,
					Policy:  ec.Policy,
					Reason:  []Reason{ReasonLicenseAllowed},
					Pass:    true,
				})
			}
		}
	}

	for _, l := range c.Licenses {
		if !l.IsSPDX() {
			// TODO: check if the config wants us to check for non-SPDX licenses
		}
		if ec.Policy.IsDenied(l) {
			evaluations = append(evaluations, LicenseEvaluation{
				License: l,
				Package: nil,
				Policy:  ec.Policy,
				Reason:  []Reason{ReasonLicenseDenied},
				Pass:    false,
			})
			continue
		}
		// otherwise, the license is allowed
		evaluations = append(evaluations, LicenseEvaluation{
			License: l,
			Package: nil,
			Policy:  ec.Policy,
			Reason:  []Reason{ReasonLicenseAllowed},
			Pass:    true,
		})
	}

	return evaluations
}

type LicenseEvaluations []LicenseEvaluation

type LicenseEvaluation struct {
	RequestID string

	// inputs into evaluation...
	License grant.License  // the license that we evaluated
	Package *grant.Package // any artifact license is evaluated with

	// what's used to evaluate...
	Policy grant.Policy // what the determination was made against

	// the output of an evaluation...
	Reason []Reason // reasons that the evaluation value the way it is
	Pass   bool     // The final evaluation
}

func (ds LicenseEvaluations) Packages() []grant.Package {
	// get the set of unique packages from the list...
	panic("not implemented")

}

func (ds LicenseEvaluations) Licenses() []grant.License {
	// get the set of unique license from the list...
	panic("not implemented")

}

func (ds LicenseEvaluations) Policies() []grant.Policy {
	// get the set of unique policies from the list...
	panic("not implemented")
}

func (ds LicenseEvaluations) IsFailed() bool {
	panic("not implemented")
}
