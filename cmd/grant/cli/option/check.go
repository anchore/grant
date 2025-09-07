package option

type Check struct {
	List                `json:",inline" yaml:",inline" mapstructure:",squash"`
	Quiet               bool     `json:"quiet" yaml:"quiet" mapstructure:"quiet"`
	RequireLicense      *bool    `json:"require-license,omitempty" yaml:"require-license,omitempty" mapstructure:"require-license"`
	RequireKnownLicense *bool    `json:"require-known-license,omitempty" yaml:"require-known-license,omitempty" mapstructure:"require-known-license"`
	Allow               []string `json:"allow" yaml:"allow" mapstructure:"allow"`
	IgnorePackages      []string `json:"ignore-packages,omitempty" yaml:"ignore-packages,omitempty" mapstructure:"ignore-packages"`
}

func DefaultCheck() Check {
	return Check{
		List:  DefaultList(),
		Quiet: false,
	}
}
