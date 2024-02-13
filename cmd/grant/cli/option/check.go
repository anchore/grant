package option

import (
	"github.com/anchore/clio"
)

type Check struct {
	List        `json:",inline" yaml:",inline" mapstructure:",squash"`
	Quiet       bool   `json:"quiet" yaml:"quiet" mapstructure:"quiet"`
	OsiApproved bool   `json:"osi-approved" yaml:"osi-approved" mapstructure:"osi-approved"`
	Rules       []Rule `json:"rules" yaml:"rules" mapstructure:"rules"`
}

func DefaultCheck() Check {
	return Check{
		List:        DefaultList(),
		Quiet:       false,
		OsiApproved: false,
		Rules:       []Rule{defaultDenyAll},
	}
}

func (o *Check) AddFlags(flags clio.FlagSet) {
	flags.BoolVarP(&o.OsiApproved, "osi-approved", "", "only allow OSI approved licenses")
}
