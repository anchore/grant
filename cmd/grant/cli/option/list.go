package option

import "github.com/anchore/clio"

type List struct {
	Output       string `json:"output" yaml:"output" mapstructure:"output"`
	ShowPackages bool   `json:"show-packages" yaml:"show-packages" mapstructure:"show-packages"`
	NonSPDX      bool   `json:"non-spdx" yaml:"non-spdx" mapstructure:"non-spdx"`
}

func DefaultList() List {
	return List{
		Output:       "table",
		ShowPackages: false,
		NonSPDX:      false,
	}
}

func (o *List) AddFlags(flags clio.FlagSet) {
	flags.BoolVarP(&o.ShowPackages, "show-packages", "", "expand the license lists to show packages that contained the detected license")
	flags.BoolVarP(&o.NonSPDX, "non-spdx", "", "show licenses that could not be matched to the SPDX license list")
	flags.StringVarP(&o.Output, "output", "o", "output format (table, json, yaml)")
}
