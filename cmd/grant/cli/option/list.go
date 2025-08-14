package option

import "github.com/anchore/clio"

type List struct {
	Output       string `json:"output" yaml:"output" mapstructure:"output"`
	ShowPackages bool   `json:"show-packages" yaml:"show-packages" mapstructure:"show-packages"`
	NonSPDX      bool   `json:"non-spdx" yaml:"non-spdx" mapstructure:"non-spdx"`
	SBOMOnly     bool   `json:"sbom-only" yaml:"sbom-only" mapstructure:"sbom-only"`
}

func DefaultList() List {
	return List{
		Output:       "table",
		ShowPackages: false,
		NonSPDX:      false,
		SBOMOnly:     false,
	}
}

func (o *List) AddFlags(flags clio.FlagSet) {
	flags.BoolVarP(&o.ShowPackages, "show-packages", "", "expand the license lists to show packages that contained the detected license")
	flags.BoolVarP(&o.NonSPDX, "non-spdx", "", "show licenses that could not be matched to the SPDX license list")
	flags.BoolVarP(&o.SBOMOnly, "sbom-only", "", "directory source: generate SBOM only and skip local license file search")
	flags.StringVarP(&o.Output, "output", "o", "output format (table, json, yaml)")
}
