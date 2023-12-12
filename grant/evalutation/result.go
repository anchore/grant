package evalutation

import (
	"github.com/anchore/grant/grant"
)

// Result is the result of a policy evaluation
// It combines the supplied case with the evaluation results
type Result struct {
	Case        grant.Case
	Evaluations LicenseEvaluations
	Pass        bool
}

type Results []Result

func NewResults(ec EvaluationConfig, cases ...grant.Case) (r Results) {
	r = make(Results, 0)
	for _, c := range cases {
		e := NewLicenseEvaluations(ec, c)
		res := Result{
			Case:        c,
			Evaluations: e,
			Pass:        !e.IsFailed(),
		}
		r = append(r, res)
	}
	return r
}

func (rs Results) IsFailed() bool {
	for _, r := range rs {
		if r.Evaluations.IsFailed() {
			return true
		}
	}
	return false
}

func (rs Results) UserInputs() []string {
	inputs := make([]string, 0)
	for _, r := range rs {
		inputs = append(inputs, r.Case.UserInput)
	}
	return inputs
}

// GetFailedEvaluations returns a map of user input to slice of failed license evaluations for that input
func (rs Results) GetFailedEvaluations(userInput string, rule grant.Rule) LicenseEvaluations {
	failed := make(LicenseEvaluations, 0)
	for _, r := range rs {
		if r.Case.UserInput == userInput && !r.Pass {
			failed = append(failed, r.Evaluations.Failed(rule)...)
		}
	}

	return failed
}

type ResultSummary struct {
	CompliantPackages int `json:"compliant_packages" yaml:"compliant_packages"`
	PackageViolations int `json:"package_violations" yaml:"package_violations"`
	IgnoredPackages   int `json:"ignored_packages" yaml:"ignored_packages"`
	LicenseViolations int `json:"license_violations" yaml:"license_violations"`
	CompliantLicenses int `json:"compliant_licenses" yaml:"compliant_licenses"`
	IgnoredLicenses   int `json:"ignored_licenses" yaml:"ignored_licenses"`
}

func (rs Results) Summary() ResultSummary {
	return ResultSummary{}
}
