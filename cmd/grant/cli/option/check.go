package option

type Check struct {
	AllowLicenses []string `json:"allow-licenses" yaml:"allow-licenses" mapstructure:"allow-licenses"`
	DenyLicenses  []string `json:"deny-licenses" yaml:"deny-licenses" mapstructure:"deny-licenses"`
}

func DefaultCheck() Check {
	return Check{
		AllowLicenses: []string{},
		DenyLicenses:  []string{"*"},
	}
}
