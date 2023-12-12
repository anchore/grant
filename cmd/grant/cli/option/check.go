package option

type Check struct {
	List  `json:",inline" yaml:",inline" mapstructure:",squash"`
	Quiet bool   `json:"quiet" yaml:"quiet" mapstructure:"quiet"`
	Rules []Rule `json:"rules" yaml:"rules" mapstructure:"rules"`
}

func DefaultCheck() Check {
	return Check{
		List:  DefaultList(),
		Quiet: false,
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
