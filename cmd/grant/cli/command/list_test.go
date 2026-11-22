package command

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_validateGroupBy(t *testing.T) {
	tests := []struct {
		name    string
		groupBy string
		wantErr string
	}{
		{
			name:    "supported field",
			groupBy: "risk",
		},
		{
			name:    "misspelled field",
			groupBy: "risks",
			wantErr: `unsupported group-by field "risks" - must be one of: risk`,
		},
		{
			name:    "unknown field",
			groupBy: "license",
			wantErr: `unsupported group-by field "license" - must be one of: risk`,
		},
		{
			name:    "wrong case is not normalised",
			groupBy: "Risk",
			wantErr: `unsupported group-by field "Risk" - must be one of: risk`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGroupBy(tt.groupBy)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.EqualError(t, err, tt.wantErr)
		})
	}
}
