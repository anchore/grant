package evalutation

type Reason struct {
	Detail string
	RuleName string
}

var (
	ReasonNoLicenseFound = "no license found"
	ReasonLicenseDenied  = "license denied by policy"
	ReasonLicenseAllowed = "license allowed by policy"
)

