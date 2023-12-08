package report

import (
	"github.com/anchore/grant/grant"
	"github.com/anchore/syft/syft/sbom"
)

// Evaluation is the result of a policy evaluation
// Grant can evaluate either an SBOM(generated on demand) or an individual license
// For any package -> license pairing and it's policy/reasoning feels like a thing
// <SOME NOUN> --> It's LIKE violations
type Result struct {
	Request     Request
	Evaluations LicenseEvaluations
	Pass        bool
}

type Results []Result

// Pass T/F + reasons for failure
// Validate() error ([]string reasons)
func (rs Results) Pass() bool {
	//
	panic("not implemented")
}

type EvaluationConfig struct {
	// Policy is the policy to evaluate against
	Policy grant.Policy
	// CheckNonSPDX is true if non-SPDX licenses should be checked
	CheckNonSPDX bool
}

// Violation is a single license violation for a given evaluation
// Package is optional as not all discovered licenses are associated with a package
//type Violation struct {
//	RequestID string
//	License   grant.License
//	Package   grant.Package
//	Reason    string
//}

//type Evaluation interface {
//	Validate() []error
//	Reasons() []string
//}

type LicenseEvaluation struct {
	RequestID string

	// inputs into evaluation...
	License grant.License  // the license that we evaluated
	Package *grant.Package // any artifact this is evaluated with

	// what's used to evaluate...
	Policy *grant.Policy // what the determination was made against

	// the output of an evaluation...
	Reason []string // reasons that the evaluation value the way it is
	Pass   bool     // The final evaluation
}

type LicenseEvaluations []LicenseEvaluation

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

func NewDeterminationFromSBOM(ec EvaluationConfig, s sbom.SBOM) Result {
	// return evalFromSBOM(ec, s)
	return Result{}
}

func NewDeterminationFromLicense(ec EvaluationConfig, l grant.License) Result {
	// return evalFromLicense(ec, l)
	return Result{}
}
