package report

import (
	"github.com/anchore/grant/grant"
	"github.com/anchore/syft/syft/sbom"
)

// Evaluation is the result of a policy evaluation
// Grant can evaluate either an SBOM(generated on demand) or an individual license
type Evaluation interface {
	GetPackages() []grant.Package
	GetLicenses() []grant.License
	GetViolations() []Violation
	GetPolicy() grant.Policy
	IsFailed() bool
}

type EvaluationConfig struct {
	// Policy is the policy to evaluate against
	Policy grant.Policy
	// CheckNonSPDX is true if non-SPDX licenses should be checked
	CheckNonSPDX bool
}

// Violation is a single license violation for a given evaluation
// Package is optional as not all discovered licenses are associated with a package
type Violation struct {
	RequestID string
	License   grant.License
	Package   grant.Package
	Reason    string
}

func NewEvaluationFromSBOM(ec EvaluationConfig, s sbom.SBOM) Evaluation {
	return evalFromSBOM(ec, s)
}

func NewEvaluationFromLicense(ec EvaluationConfig, l grant.License) Evaluation {
	return evalFromLicense(ec, l)
}
