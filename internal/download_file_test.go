package internal

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_DownloadFile(t *testing.T) {
	contents := `this is the file!`
	expectedDigest := "fd979f1e39618058000d02793baa4694afb1a1ba1a463b1a543806992be5b5b2"
	tests := []struct {
		name     string
		checksum string
		wantErr  require.ErrorAssertionFunc
	}{
		{
			name:     "happy path",
			checksum: expectedDigest,
		},
		{
			name:     "mismatched checksum",
			checksum: "805694affd979f1438069800e3961b1a1ba50d02793baa492be5b5b2a1a463b1",
			wantErr:  require.Error,
		},
		{
			name:     "missing checksum",
			checksum: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "GET", r.Method)
				_, err := w.Write([]byte(contents))
				require.NoError(t, err)
				return
			}))
			t.Cleanup(s.Close)

			dir := t.TempDir()
			dlPath := filepath.Join(dir, "the-file-path.txt")

			tt.wantErr(t, DownloadFile(s.URL, dlPath, tt.checksum))

			gotContents, err := os.ReadFile(dlPath)
			require.NoError(t, err)

			assert.Equal(t, contents, string(gotContents))
		})
	}
}
