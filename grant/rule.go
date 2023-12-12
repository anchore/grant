package grant

import "github.com/gobwas/glob"

type Rules []Rule

type Rule struct {
	Name               string
	Reason             string
	Glob               glob.Glob
	OriginalPattern    string
	Exceptions         []glob.Glob
	OriginalExceptions []string
	Mode               RuleMode
	Severity           RuleSeverity
}

type RuleMode string

type RuleSeverity string

const (
	Critical RuleSeverity = "critical"
	High     RuleSeverity = "high"
	Medium   RuleSeverity = "medium"
	Low      RuleSeverity = "low"
)

const (
	Allow  RuleMode = "allow"
	Deny   RuleMode = "deny"
	Ignore RuleMode = "ignore"
)
