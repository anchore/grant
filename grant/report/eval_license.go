package report

import (
	"github.com/anchore/grant/grant"
)

type licenseEval struct {
	// license is the license that was evaluated
	license grant.License
	// policy is the policy used to evaluate the license
	policy grant.Policy
}

func (e *licenseEval) IsFailed() bool {
	return true
}

func (e *licenseEval) GetPackages() []grant.Package {
	return []grant.Package{}
}

func (e *licenseEval) GetLicenses() []grant.License {
	return []grant.License{e.license}
}

func (e *licenseEval) GetViolations() []Violation {
	return []Violation{}
}

func (e *licenseEval) GetPolicy() grant.Policy {
	return e.policy
}

func evalFromLicense(ec EvaluationConfig, l grant.License) Evaluation {
	return &licenseEval{
		license: l,
		policy:  ec.Policy,
	}
}
