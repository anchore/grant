package internal

import "testing"

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
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if got := wrappedColumnWidth(tt.terminalWidth); got != tt.want {
				t.Errorf("wrappedColumnWidth(%d) = %d, want %d", tt.terminalWidth, got, tt.want)
			}
		})
	}
}
