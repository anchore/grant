package evalutation

type Reason struct {
	Detail   string
	RuleName string
}

var (
	RuleNameNotOSIApproved = "not OSI"
)

var (
	ReasonNoLicenseFound      = "no license found"
	ReasonLicenseDeniedPolicy = "license denied by policy"
	ReasonLicenseAllowed      = "license allowed by policy"
	ReasonLicenseDeniedOSI    = "license not OSI approved"
)

func NewReason(detail, ruleName string) Reason {
	return Reason{
		Detail:   detail,
		RuleName: ruleName,
	}
}
