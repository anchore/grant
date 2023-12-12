package evalutation

import (
	"sort"

	"github.com/anchore/grant/grant"
	"github.com/anchore/syft/syft/sbom"
)

func NewLicenseEvaluations(ec EvaluationConfig, c grant.Case) LicenseEvaluations {
	evaluations := make([]LicenseEvaluation, 0)
	for _, sb := range c.SBOMS {
		evaluations = checkSBOM(ec, c, sb)
	}

	for _, l := range c.Licenses {
		le := checkLicense(ec, nil, l)
		evaluations = append(evaluations, le)
	}

	return evaluations
}

func checkSBOM(ec EvaluationConfig, c grant.Case, sb sbom.SBOM) LicenseEvaluations {
	evaluations := make([]LicenseEvaluation, 0)
	for pkg := range sb.Artifacts.Packages.Enumerate() {
		// since we use syft as a library to generate the sbom we need to convert its packages/licenses to grant types
		grantPkg := convertSyftPackage(pkg)
		if len(grantPkg.Licenses) == 0 {
			// We need to include an evaluation that shows this package has no licenses
			le := NewLicenseEvaluation(grant.License{}, grantPkg, ec.Policy, []Reason{{
				Detail: ReasonNoLicenseFound,
			}}, true)
			evaluations = append(evaluations, le)
			continue
		}

		for _, l := range grantPkg.Licenses {
			le := checkLicense(ec, grantPkg, l)
			evaluations = append(evaluations, le)
		}
	}
	return evaluations
}

func checkLicense(ec EvaluationConfig, pkg *grant.Package, l grant.License) LicenseEvaluation {
	if !l.IsSPDX() && ec.CheckNonSPDX {
		if denied, rule := ec.Policy.IsDenied(l, pkg); denied {
			var reason Reason
			if rule != nil {
				reason = Reason{
					Detail:   ReasonLicenseDeniedPolicy,
					RuleName: rule.Name,
				}
			}
			return NewLicenseEvaluation(l, pkg, ec.Policy, []Reason{reason}, false)
		}
	}

	if ec.OsiApproved && l.IsSPDX() {
		if !l.IsOsiApproved {
			return NewLicenseEvaluation(l, pkg, ec.Policy, []Reason{{
				Detail:   ReasonLicenseDeniedOSI,
				RuleName: RuleNameNotOSIApproved,
			}}, false)
		}
	}
	if denied, rule := ec.Policy.IsDenied(l, pkg); denied {
		var reason Reason
		if rule != nil {
			reason = Reason{
				Detail:   ReasonLicenseDeniedPolicy,
				RuleName: rule.Name,
			}
		}
		return NewLicenseEvaluation(l, pkg, ec.Policy, []Reason{reason}, false)
	}

	return NewLicenseEvaluation(l, pkg, ec.Policy, []Reason{{
		Detail: ReasonLicenseAllowed,
	}}, true)
}

type LicenseEvaluations []LicenseEvaluation

func (le LicenseEvaluations) Packages(license string) []string {
	packages := make([]string, 0)
	// get the set of unique packages from the list...
	packageMap := make(map[string]struct{})
	for _, e := range le {
		if e.Package != nil && (e.License.LicenseID == license || e.License.Name == license) {
			if _, ok := packageMap[e.Package.Name]; !ok {
				packageMap[e.Package.Name] = struct{}{}
				packages = append(packages, e.Package.Name)
			}
		}
	}
	sort.Sort(sort.StringSlice(packages))
	return packages
}

func (le LicenseEvaluations) EmptyPackages() []string {
	packages := make([]string, 0)
	// get the set of unique packages from the list...
	packageMap := make(map[string]struct{})
	for _, e := range le {
		if e.Package != nil && e.License.LicenseID == "" && e.License.Name == "" {
			if _, ok := packageMap[e.Package.Name]; !ok {
				packageMap[e.Package.Name] = struct{}{}
				packages = append(packages, e.Package.Name)
			}
		}
	}
	sort.Sort(sort.StringSlice(packages))
	return packages
}

func (le LicenseEvaluations) Licenses(pkg string) []grant.License {
	licenses := make([]grant.License, 0)
	licenseMap := make(map[string]struct{})
	// get the set of unique licenses from the list for the given package...
	for _, e := range le {
		if e.Package != nil && e.Package.Name == pkg {
			if _, ok := licenseMap[e.License.LicenseID]; !ok && e.License.SPDXExpression != "" {
				licenseMap[e.License.LicenseID] = struct{}{}
				licenses = append(licenses, e.License)
			}
			if _, ok := licenseMap[e.License.Name]; !ok && e.License.Name != "" {
				licenseMap[e.License.Name] = struct{}{}
				licenses = append(licenses, e.License)
			}
		}
	}
	return licenses
}

func (le LicenseEvaluations) GetLicenses() []string {
	licenses := make([]string, 0)
	licenseMap := make(map[string]struct{})
	// get the set of unique licenses from the list for the given package...
	for _, e := range le {
		if _, ok := licenseMap[e.License.SPDXExpression]; !ok && e.License.SPDXExpression != "" {
			licenseMap[e.License.LicenseID] = struct{}{}
			licenses = append(licenses, e.License.SPDXExpression)
		}
		if _, ok := licenseMap[e.License.Name]; !ok && e.License.Name != "" {
			licenseMap[e.License.Name] = struct{}{}
			licenses = append(licenses, e.License.Name)
		}
	}
	sort.Sort(sort.StringSlice(licenses))
	return licenses
}

func (le LicenseEvaluations) Failed(r grant.Rule) LicenseEvaluations {
	var failed LicenseEvaluations
	for _, e := range le {
		if !e.Pass && e.RuleApplied(r) {
			failed = append(failed, e)
		}
	}
	sort.Sort(failed)
	return failed
}

func (le LicenseEvaluations) IsFailed() bool {
	for _, e := range le {
		if !e.Pass {
			return true
		}
	}
	return false
}

type LicenseEvaluation struct {
	// inputs into evaluation...
	License grant.License  // the license that we evaluated
	Package *grant.Package // any artifact license is evaluated with

	// what's used to evaluate...
	Policy grant.Policy // what the determination was made against

	// the output of an evaluation...
	Reason []Reason // reasons that the evaluation value the way it is
	Pass   bool     // The final evaluation
}

func (le LicenseEvaluation) RuleApplied(r grant.Rule) bool {
	for _, reason := range le.Reason {
		if reason.RuleName == r.Name {
			return true
		}
	}
	return false
}

func NewLicenseEvaluation(license grant.License, pkg *grant.Package, policy grant.Policy, reasons []Reason, pass bool) LicenseEvaluation {
	return LicenseEvaluation{
		License: license,
		Package: pkg,
		Policy:  policy,
		Reason:  reasons,
		Pass:    pass,
	}
}

func (le LicenseEvaluations) Len() int { return len(le) }
func (le LicenseEvaluations) Less(i, j int) bool {
	var compareI, compareJ string
	if le[i].License.LicenseID != "" {
		compareI = le[i].License.LicenseID
	} else {
		compareI = le[i].License.Name
	}
	if le[j].License.LicenseID != "" {
		compareJ = le[j].License.LicenseID
	} else {
		compareJ = le[j].License.Name
	}
	return compareI < compareJ
}
func (le LicenseEvaluations) Swap(i, j int) { le[i], le[j] = le[j], le[i] }
