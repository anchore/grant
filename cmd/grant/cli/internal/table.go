package internal

import (
	"github.com/jedib0t/go-pretty/v6/table"
)

// minWrappedColumnWidth keeps a wrapped column readable on a narrow terminal.
const minWrappedColumnWidth = 20

// wrappedColumnWidth returns the width to allow a wide text column, given the
// width of the terminal. A terminal width of 0 means the width is unknown (the
// output is not a terminal), in which case nothing should be wrapped.
func wrappedColumnWidth(terminalWidth int) int {
	if terminalWidth <= 0 {
		return 0
	}

	width := terminalWidth / 2
	if width < minWrappedColumnWidth {
		width = minWrappedColumnWidth
	}

	return width
}

// WrapWideColumns limits the named columns to a share of the terminal width, so
// that a package carrying many licenses wraps instead of pushing the row far
// past the edge of the screen. It is a no-op when stdout is not a terminal, so
// piped and redirected output keeps its current shape.
func WrapWideColumns(t table.Writer, columns ...string) {
	width := wrappedColumnWidth(TerminalWidth())
	if width == 0 {
		return
	}

	configs := make([]table.ColumnConfig, 0, len(columns))
	for _, name := range columns {
		configs = append(configs, table.ColumnConfig{Name: name, WidthMax: width})
	}

	t.SetColumnConfigs(configs)
}
