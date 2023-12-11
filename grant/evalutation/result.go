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

// GetFailedEvaluations returns a map of user input to slice of failed license evaluations for that input
func (rs Results) GetFailedEvaluations() map[string]LicenseEvaluations {
	failures := make(map[string]LicenseEvaluations)
	for _, r := range rs {
		if r.Evaluations.IsFailed() {
			failures[r.Case.UserInput] = r.Evaluations.Failed()
		}
	}
	return failures
}
