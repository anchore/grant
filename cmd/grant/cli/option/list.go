package option

import "github.com/anchore/clio"

type List struct {
	Format       string `json:"format" yaml:"format" mapstructure:"format"`
	ShowPackages bool   `json:"show-packages" yaml:"show-packages" mapstructure:"show-packages"`
	CheckNonSPDX bool   `json:"check-non-spdx" yaml:"check-non-spdx" mapstructure:"check-non-spdx"`
}

func DefaultList() List {
	return List{
		Format:       "table",
		ShowPackages: false,
		CheckNonSPDX: false,
	}
}

func (o *List) AddFlags(flags clio.FlagSet) {
	flags.BoolVarP(&o.ShowPackages, "show-packages", "", "expand the license lists to show packages that contained the detected license")
	flags.BoolVarP(&o.CheckNonSPDX, "check-non-spdx", "", "show licenses that could not be matched to the SPDX license list")
}
