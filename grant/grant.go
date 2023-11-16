package grant

import (
	"slices"
	"strings"

	"github.com/anchore/grant/cmd/grant/cli/option"
)

func IsAllowed(cfg option.Check, license string) bool {
	return isAllowed(cfg, license)
}

// deny licenses take precidence over allow licenses by default
// if a license is in both lists, it is denied
// if a license is in neither list, it is denied; this is the default behavior
// licenses are matched on a case-insensitive basis
// TODO: add support for glob matching expressions; for now, only exact matches are supported
func isAllowed(cfg option.Check, license string) bool {
	if slices.Contains(cfg.DenyLicenses, "*") {
		// all licenses are denied by default
		// if a license is not in the allow list, then it is a forbidden license
		if slices.Contains(cfg.AllowLicenses, strings.ToLower(license)) {
			return true
		}
		return false
	}
	// user has explicitly denied licenses (no licenses are denied by default)
	if slices.Contains(cfg.DenyLicenses, license) {
		return false
	}

	return true
}
