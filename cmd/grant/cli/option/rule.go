package option

type Rule struct {
	Name       string   `json:"name" yaml:"name" mapstructure:"name"`
	Reason     string   `json:"reason" yaml:"reason" mapstructure:"reason"`
	Pattern    string   `json:"pattern" yaml:"pattern" mapstructure:"pattern"`
	Severity   string   `json:"severity" yaml:"severity" mapstructure:"severity"`
	Mode       string   `json:"mode" yaml:"mode" mapstructure:"mode"`
	Exceptions []string `json:"exceptions" yaml:"exceptions" mapstructure:"exceptions"`
}

var defaultDenyAll = Rule{
	Name:    "default-deny-all",
	Reason:  "grant by default will deny all licenses",
	Mode:    "deny",
	Pattern: "*",
}
