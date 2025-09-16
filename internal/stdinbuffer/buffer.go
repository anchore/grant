package stdinbuffer

import (
	"bytes"
	"io"
	"sync"
)

var (
	mu     sync.Mutex
	buffer *bytes.Reader
)

// Set stores stdin data that was read but needs to be processed later
func Set(data []byte) {
	mu.Lock()
	defer mu.Unlock()
	buffer = bytes.NewReader(data)
}

// Get retrieves the stored stdin data and clears the buffer
func Get() io.ReadSeeker {
	mu.Lock()
	defer mu.Unlock()

	if buffer == nil {
		return nil
	}

	// Reset seek position to beginning
	buffer.Seek(0, io.SeekStart)

	// Return the buffer and clear it for next use
	b := buffer
	buffer = nil
	return b
}

// HasData checks if there's data in the buffer
func HasData() bool {
	mu.Lock()
	defer mu.Unlock()
	return buffer != nil
}