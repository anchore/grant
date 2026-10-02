package internal

import (
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/gookit/color"
	"github.com/jedib0t/go-pretty/v6/text"

	"github.com/anchore/grant/internal/spdxlicense"
)

// minWrappedColumnWidth keeps a wrapped column readable on a narrow terminal.
const minWrappedColumnWidth = 20

// wrappedColumnWidth returns the width to allow a license column, given the
// width of the terminal. A terminal width of 0 means the width is unknown (the
// output is not a terminal), in which case nothing should be wrapped.
func wrappedColumnWidth(terminalWidth int) int {
	if terminalWidth <= 0 {
		return 0
	}
	return max(terminalWidth/2, minWrappedColumnWidth)
}

// LicenseColumnWidth returns the width license cells should wrap to: half the
// terminal width, or 0 (no wrapping) when stdout is not a terminal, so piped
// and redirected output keeps its current shape.
func LicenseColumnWidth() int {
	return wrappedColumnWidth(terminalWidth())
}

// LicensePart is one license in a license cell. Text is the plain text that is
// measured and wrapped. Link and Color are applied only after wrapping, so an
// escape sequence is never split across lines.
type LicensePart struct {
	Text  string
	Link  string
	Color func(string) string
}

// ClickableLicense returns a blue, hyperlinked part when the license is a known
// SPDX ID, and a plain part otherwise.
func ClickableLicense(name string) LicensePart {
	return spdxPart(name, sgr("34"), nil)
}

// spdxPart links the license to its SPDX reference when there is one, using
// linked as the color, and falls back to plain (or the given color) otherwise.
func spdxPart(name string, linked, plain func(string) string) LicensePart {
	if l, err := spdxlicense.GetLicenseByID(name); err == nil && l.Reference != "" {
		return LicensePart{Text: name, Link: l.Reference, Color: linked}
	}
	return LicensePart{Text: name, Color: plain}
}

// LicenseCell renders license parts for a table cell, joined with ", " and
// followed by "(+n more)" when more > 0. When that is wider than width, every
// part goes on its own line, and a part that is still too wide is soft wrapped.
// A width of 0 means no limit.
func LicenseCell(width int, parts []LicensePart, more int) string {
	if more > 0 {
		// clip so the append never writes into the caller's backing array
		parts = append(slices.Clip(parts), LicensePart{Text: fmt.Sprintf("(+%d more)", more), Color: colorize(color.Gray)})
	}

	plain := make([]string, len(parts))
	for i, p := range parts {
		plain[i] = SanitizeText(p.Text)
	}
	stack := width > 0 && text.StringWidthWithoutEscSequences(joinLicenses(plain, more > 0)) > width

	rendered := make([]string, len(parts))
	for i, p := range parts {
		s := plain[i]
		// ponytail: a link is never split since that breaks it, so an SPDX ID longer
		// than the column overflows. The longest is ~40 chars, past the 20 floor only
		// on very narrow terminals.
		if stack && p.Link == "" && text.StringWidthWithoutEscSequences(s) > width {
			s = text.WrapSoft(s, width)
		}
		rendered[i] = style(p, s)
	}

	if stack {
		return strings.Join(rendered, "\n")
	}
	return joinLicenses(rendered, more > 0)
}

// joinLicenses joins licenses with ", ", attaching a trailing "(+n more)" with a
// space instead.
func joinLicenses(s []string, hasMore bool) string {
	if !hasMore {
		return strings.Join(s, ", ")
	}
	return strings.Join(s[:len(s)-1], ", ") + " " + s[len(s)-1]
}

// style applies color and hyperlink to each line on its own, so every line
// carries a complete, terminated escape sequence.
func style(p LicensePart, s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if p.Color != nil {
			line = p.Color(line)
		}
		if p.Link != "" {
			line = fmt.Sprintf("\033]8;;%s\033\\%s\033]8;;\033\\", p.Link, line)
		}
		lines[i] = line
	}
	return strings.Join(lines, "\n")
}

// SanitizeText drops control characters (including ESC) from text that came
// from an SBOM, so a package or license name cannot inject terminal escape
// sequences (window titles, clipboard writes, fake links) into the output.
func SanitizeText(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

// colorize adapts a gookit color, which honors NO_COLOR and friends.
func colorize(c color.Color) func(string) string {
	return func(s string) string { return c.Sprint(s) }
}

// sgr returns a func that wraps text in the given SGR color code. It is used
// inside hyperlinks, matching the escapes these cells emitted before.
func sgr(code string) func(string) string {
	return func(s string) string {
		return "\033[" + code + "m" + s + "\033[0m"
	}
}
