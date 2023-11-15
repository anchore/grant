package option

type Check struct {
	Precidence    []string `json:"precidence" yaml:"precidence" mapstructure:"precidence"`
	DenyLicenses  []string `json:"deny-licenses" yaml:"deny-licenses" mapstructure:"deny-licenses"`
	AllowLicenses []string `json:"allow-licenses" yaml:"allow-licenses" mapstructure:"allow-licenses"`
}

func DefaultCheck() Check {
	return Check{
		Precidence:    []string{"deny", "allow"},
		DenyLicenses:  []string{"*"},
		AllowLicenses: []string{},
	}
}
