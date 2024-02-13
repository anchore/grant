package cli

import (
	"log"
	"os"
	"os/exec"
	"testing"
)

const grantTmpPath = "../../.tmp/grant"

func buildBinary() (string, error) {
	buildCmd := exec.Command("go", "build", "-o", grantTmpPath, "../../cmd/grant/main.go") // Adjust the last argument to your package path if necessary
	err := buildCmd.Run()
	return grantTmpPath, err
}

// setup function that you want to run before any tests
func setup(m *testing.M) {
	_, err := buildBinary()
	if err != nil {
		log.Fatalf("Failed to build binary: %v", err)
	}
}

// teardown function to clean up after the tests
func teardown() {
	// Your cleanup code here
	println("Running teardown after all tests.")
}

// TestMain is the entry point for testing
func TestMain(m *testing.M) {
	setup(m)        // Call setup
	code := m.Run() // Run the tests and store the result
	teardown()      // Call teardown
	os.Exit(code)   // Exit with the result of the tests
}
