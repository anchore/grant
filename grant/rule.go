package grant

import "github.com/gobwas/glob"

type Rules []Rule

type Rule struct {
	Glob       glob.Glob
	Exceptions []glob.Glob
	Mode       RuleMode
	Reason     string
}

type RuleMode string

const (
	Allow  RuleMode = "allow"
	Deny   RuleMode = "deny"
	Ignore RuleMode = "ignore"
)
