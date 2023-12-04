package cli

import "testing"

func Test_VersionCommand(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{
			name:    "text output",
			command: "version",
		},
		{
			name:    "json output",
			command: "version -o json",
		},
		{
			name:    "root command short version output",
			command: "--version",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

		})
	}
}
