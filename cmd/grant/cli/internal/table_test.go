package internal

import (
	"regexp"
	"strings"
	"testing"

	"github.com/gookit/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/stretchr/testify/assert"
)

// escapes matches the SGR and OSC 8 sequences license cells emit. text.StripEscape
// is not used since it mis-parses OSC 8 and can swallow text across lines.
var escapes = regexp.MustCompile("\x1b\\[[0-9;]*m|\x1b\\]8;;[^\x1b]*\x1b\\\\")

func stripEscapes(s string) string {
	return escapes.ReplaceAllString(s, "")
}

func TestWrappedColumnWidth(t *testing.T) {
	tests := []struct {
		name          string
		terminalWidth int
		want          int
	}{
		{name: "unknown width does not wrap", terminalWidth: 0, want: 0},
		{name: "negative width does not wrap", terminalWidth: -1, want: 0},
		{name: "wide terminal gets half its width", terminalWidth: 178, want: 89},
		{name: "narrow terminal keeps a readable minimum", terminalWidth: 30, want: minWrappedColumnWidth},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, wrappedColumnWidth(tt.terminalWidth))
		})
	}
}

func TestLicenseCell(t *testing.T) {
	rpm := "ASL 1.1 and ASL 2.0 and BSD and BSD with advertising and GPL+ and GPLv2"

	tests := []struct {
		name  string
		width int
		parts []string
		more  int
		want  string
	}{
		{name: "no limit joins on one line", width: 0, parts: []string{"MIT", "Apache-2.0"}, more: 3, want: "MIT, Apache-2.0 (+3 more)"},
		{name: "fits joins on one line", width: 40, parts: []string{"MIT", "Apache-2.0"}, more: 3, want: "MIT, Apache-2.0 (+3 more)"},
		{name: "too wide puts each license on its own line", width: 20, parts: []string{"MIT", "Apache-2.0"}, more: 3, want: "MIT\nApache-2.0\n(+3 more)"},
		{name: "long expression soft wraps on words", width: 30, parts: []string{rpm}, want: text.WrapSoft(rpm, 30)},
		{name: "no limit leaves a long expression alone", width: 0, parts: []string{rpm}, want: rpm},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var parts []LicensePart
			for _, p := range tt.parts {
				parts = append(parts, LicensePart{Text: p})
			}
			got := LicenseCell(tt.width, parts, tt.more)
			assert.Equal(t, tt.want, stripEscapes(got))
			for _, line := range strings.Split(got, "\n") {
				if tt.width > 0 {
					assert.LessOrEqual(t, text.StringWidthWithoutEscSequences(line), tt.width, "line %q", line)
				}
				// no license or note is split mid-word
				assert.False(t, strings.HasPrefix(stripEscapes(line), "-"), "line %q", line)
			}
		})
	}
}

// TestLicenseCellRendersIntactLinks renders through go-pretty, since splitting a
// hyperlink across lines is what broke in the first place. It runs with gookit
// color on and off (NO_COLOR), since that changes which parts carry escapes.
func TestLicenseCellRendersIntactLinks(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(map[bool]string{true: "color", false: "no color"}[enabled], func(t *testing.T) {
			prev := color.Enable
			color.Enable = enabled
			t.Cleanup(func() { color.Enable = prev })

			parts := []LicensePart{
				ClickableLicense("LGPL-2.1-or-later"),
				ClickableLicense("Apache-2.0"),
			}
			cell := LicenseCell(20, parts, 3)

			tw := table.NewWriter()
			tw.AppendHeader(table.Row{"NAME", "LICENSE", "RISK"})
			tw.AppendRow(table.Row{"multi", cell, "High"})
			out := tw.Render()

			for _, line := range strings.Split(out, "\n") {
				opens := strings.Count(line, "\033]8;;https://")
				closes := strings.Count(line, "\033]8;;\033\\")
				assert.Equal(t, opens, closes, "unbalanced hyperlink on line %q", line)
				assert.NotContains(t, line, "\033[8m", "conceal escape leaked into line %q", line)
			}
			plain := stripEscapes(out)
			assert.NotContains(t, plain, "\x1b", "unexpected escape left after stripping")
			for _, id := range []string{"LGPL-2.1-or-later", "Apache-2.0", "(+3 more)"} {
				assert.Contains(t, plain, id)
			}
		})
	}
}

func TestSanitizeText(t *testing.T) {
	assert.Equal(t, "evil]0;pwnedname", SanitizeText("evil\x1b]0;pwned\x07name"))
	assert.Equal(t, "GPL-2.0-only", SanitizeText("GPL-2.0-only"))
	assert.Equal(t, "ab", SanitizeText("a\u009bb"), "C1 CSI is dropped too")

	// license text is sanitized before the cell adds its own escapes
	cell := LicenseCell(0, []LicensePart{{Text: "MIT\x1b]52;c;aGk=\x07"}}, 0)
	assert.Equal(t, "MIT]52;c;aGk=", cell)
}
