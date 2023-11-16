package internal

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/anchore/grant/internal/log"
)

func DownloadFile(url string, filepath string, checksum string) (err error) {
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	resp, err := http.Get(url) // nolint:gosec
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	// take sha256 of file and compare with checksum while copying to disk
	h := sha256.New()
	tee := io.TeeReader(resp.Body, h)

	if _, err := io.Copy(out, tee); err != nil {
		return err
	}

	if checksum != "" {
		if checksum != fmt.Sprintf("%x", h.Sum(nil)) {
			return fmt.Errorf("checksum mismatch for %q", filepath)
		}

		log.WithFields("checksum", checksum, "asset", filepath, "url", url).Trace("checksum verified")
	}

	return nil
}
