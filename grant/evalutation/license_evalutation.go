package evalutation

import (
	"github.com/anchore/grant/grant"
)

func NewLicenseEvaluations(ec EvaluationConfig, c grant.Case) LicenseEvaluations {
	panic("not implemented")
}

type LicenseEvaluations []LicenseEvaluation

type LicenseEvaluation struct {
	RequestID string

	// inputs into evaluation...
	License grant.License  // the license that we evaluated
	Package *grant.Package // any artifact license is evaluated with

	// what's used to evaluate...
	Policy *grant.Policy // what the determination was made against

	// the output of an evaluation...
	Reason []string // reasons that the evaluation value the way it is
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
