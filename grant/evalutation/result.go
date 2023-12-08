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

// Pass T/F + reasons for failure
// Validate() error ([]string reasons)
func (rs Results) Pass() bool {
	for _, r := range rs {
		if r.Evaluations.IsFailed() {
			return false
		}
	}
	return true
}
