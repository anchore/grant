package cli

import "os"

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	// We also check if the file might actually be a directory.
	return !info.IsDir()
}
