package evalutation

import "github.com/anchore/grant/grant"

type EvaluationConfig struct {
	// Policy is the policy to evaluate against
	// if non is supplied, the default policy is used (grant.DefaultPolicy())
	Policy grant.Policy
	// CheckNonSPDX is true if non-SPDX licenses should be checked
	CheckNonSPDX bool
	// OsiApproved is true if only OSI approved licenses are the only ones allowed
	OsiApproved bool
}

func DefaultEvaluationConfig() EvaluationConfig {
	return EvaluationConfig{
		Policy:       grant.DefaultPolicy(),
		CheckNonSPDX: false,
	}
}
