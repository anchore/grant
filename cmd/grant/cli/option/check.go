package option

import "github.com/anchore/clio"

type Check struct {
	Format       string `json:"format" yaml:"format" mapstructure:"format"`
	ShowPackages bool   `json:"show-packages" yaml:"show-packages" mapstructure:"show-packages"`
	CheckNonSPDX bool   `json:"check-non-spdx" yaml:"check-non-spdx" mapstructure:"check-non-spdx"`
	Quiet        bool   `json:"quiet" yaml:"quiet" mapstructure:"quiet"`
	Rules        []Rule `json:"rules" yaml:"rules" mapstructure:"rules"`
}

func (o *Check) AddFlags(flags clio.FlagSet) {
	flags.BoolVarP(&o.ShowPackages, "show-packages", "", "expand the license lists to show packages that contained the license violation")
	flags.BoolVarP(&o.CheckNonSPDX, "check-non-spdx", "", "run the configured rules against licenses that could not be matched to the SPDX license list")
}

func DefaultCheck() Check {
	return Check{
		ShowPackages: false,
		CheckNonSPDX: false,
		Quiet:        false,
		Rules: []Rule{
			{
				Name:     "deny-all",
				Reason:   "grant by default will deny all licenses",
				Pattern:  "*",
				Severity: "high",
			},
		},
	}
}
