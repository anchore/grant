package option

type Rule struct {
	Name       string   `json:"name" yaml:"name" mapstructure:"name"`
	Reason     string   `json:"reason" yaml:"reason" mapstructure:"reason"`
	Pattern    string   `json:"pattern" yaml:"pattern" mapstructure:"pattern"`
	Severity   string   `json:"severity" yaml:"severity" mapstructure:"severity"`
	Exceptions []string `json:"exceptions" yaml:"exceptions" mapstructure:"exceptions"`
}
