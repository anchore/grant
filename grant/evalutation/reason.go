package evalutation

import (
	"github.com/anchore/grant/grant"
)

type Reason string

var (
	ReasonNoLicenseFound Reason = "no license found"
	ReasonLicenseDenied  Reason = "license denied by policy"
	ReasonLicenseAllowed Reason = "license allowed by policy"
)

func NewRuleReason(rule grant.Rule) Reason {
	return Reason(rule.Reason)
}
