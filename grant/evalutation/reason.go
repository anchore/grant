package evalutation

type Reason string

var (
	ReasonNoLicenseFound Reason = "no license found"
	ReasonLicenseDenied  Reason = "license denied by policy"
	ReasonLicenseAllowed Reason = "license allowed by policy"
)
