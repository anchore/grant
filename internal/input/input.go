package input

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
)

// IsStdinPipeOrRedirect returns true if stdin is provided via pipe or redirect
func IsStdinPipeOrRedirect() (bool, error) {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false, fmt.Errorf("unable to determine if there is piped input: %w", err)
	}

	// note: we should NOT use the absence of a character device here as the hint that there may be input expected
	// on stdin, as running grant as a subprocess you would expect no character device to be present but input can
	// be from either stdin or indicated by the CLI. Checking if stdin is a pipe is the most direct way to determine
	// if there *may* be bytes that will show up on stdin that should be used for the analysis source.
	return fi.Mode()&os.ModeNamedPipe != 0 || fi.Size() > 0, nil
}

func GetReader(src string) (io.ReadSeeker, error) {
	switch src {
	case "-":
		return decodeStdin(os.Stdin)
	default:
		fileLocation, err := homedir.Expand(src)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("could not check licenses; could not expand path: %s ", src))
		}

		reader, err := os.Open(fileLocation)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("could not check licenses; could not open file: %s ", fileLocation))
		}
		return reader, nil
	}
}

func decodeStdin(r io.Reader) (io.ReadSeeker, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed reading stdin: %w", err)
	}

	reader := bytes.NewReader(b)
	_, err = reader.Seek(0, io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf("failed to parse stdin: %w", err)
	}

	return reader, nil
}
