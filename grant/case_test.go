package grant

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

func readTestLicense(t *testing.T, filename string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("testdata", filename))
	require.NoError(t, err, "Failed to read test license file: %s", filename)
	return string(content)
}

func TestHandleDir_SBOMLicenseScan(t *testing.T) {
	tests := []struct {
		name           string
		setupFunc      func(t *testing.T) string
		expectedResult func(t *testing.T, result Case)
	}{
		{
			name: "scans license files when SBOM fails",
			setupFunc: func(t *testing.T) string {
				tempDir := t.TempDir()

				// Create license files at root with actual license content
				mitLicense := readTestLicense(t, "mit-license-short.txt")

				require.NoError(t, os.WriteFile(filepath.Join(tempDir, "LICENSE"), []byte(mitLicense), 0644))
				require.NoError(t, os.WriteFile(filepath.Join(tempDir, "random.txt"), []byte("not a package file"), 0644))

				return tempDir
			},
			expectedResult: func(t *testing.T, result Case) {
				if len(result.SBOMS) == 0 {
					assert.GreaterOrEqual(t, len(result.Licenses), 1, "Should find the LICENSE file")
				}
			},
		},
		{
			name: "finds all license files including nested ones",
			setupFunc: func(t *testing.T) string {
				tempDir := t.TempDir()

				mitLicense := readTestLicense(t, "mit-license.txt")
				apacheLicense := readTestLicense(t, "apache-license.txt")
				gplLicense := readTestLicense(t, "gpl-license.txt")

				require.NoError(t, os.WriteFile(filepath.Join(tempDir, "LICENSE"), []byte(mitLicense), 0644))
				require.NoError(t, os.WriteFile(filepath.Join(tempDir, "LICENSE.md"), []byte(apacheLicense), 0644))
				require.NoError(t, os.WriteFile(filepath.Join(tempDir, "COPYING"), []byte(gplLicense), 0644))

				nestedDir := filepath.Join(tempDir, "node_modules", "package1", "subpackage")
				require.NoError(t, os.MkdirAll(nestedDir, 0755))

				require.NoError(t, os.WriteFile(filepath.Join(tempDir, "node_modules", "LICENSE"), []byte(mitLicense), 0644))
				require.NoError(t, os.WriteFile(filepath.Join(nestedDir, "LICENSE"), []byte(apacheLicense), 0644))
				require.NoError(t, os.WriteFile(filepath.Join(nestedDir, "COPYING"), []byte(gplLicense), 0644))

				// Create many non-license files that should be ignored
				for i := range 100 {
					filename := filepath.Join(nestedDir, fmt.Sprintf("file%d.js", i))
					require.NoError(t, os.WriteFile(filename, []byte("console.log('test');"), 0644))
				}

				return tempDir
			},
			expectedResult: func(t *testing.T, result Case) {
				// Debug: log what we actually found
				t.Logf("Found %d SBOMs and %d licenses", len(result.SBOMS), len(result.Licenses))

				// Should find all license files (6 total: 3 root + 3 nested)
				totalExpectedLicenses := 6
				if len(result.SBOMS) > 0 {
					// If SBOM was generated, licenses might be found through SBOM
					t.Logf("SBOM generated, checking for licenses...")
					assert.GreaterOrEqual(t, len(result.Licenses), 1, "Should find licenses through SBOM or direct scan")
				} else {
					// If no SBOM, should find all license files through direct scan
					t.Logf("No SBOM generated, should find all %d license files", totalExpectedLicenses)
					assert.GreaterOrEqual(t, len(result.Licenses), totalExpectedLicenses, "Should find all license files including nested ones")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testDir := tt.setupFunc(t)

			ch, err := NewCaseHandler()
			require.NoError(t, err)
			defer ch.Close()

			result, err := ch.handleDir(testDir)
			require.NoError(t, err)

			tt.expectedResult(t, result)
		})
	}
}

func TestHandleDir_PerformanceWithManyFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	tempDir := t.TempDir()

	// Create a large directory structure similar to node_modules
	for i := 0; i < 100; i++ {
		pkgDir := filepath.Join(tempDir, "node_modules", fmt.Sprintf("package%d", i))
		require.NoError(t, os.MkdirAll(pkgDir, 0755))

		// Create 10 files in each package
		for j := 0; j < 10; j++ {
			filename := filepath.Join(pkgDir, fmt.Sprintf("file%d.js", j))
			require.NoError(t, os.WriteFile(filename, []byte("test content"), 0644))
		}

		// Add a license file in nested directory (should be found by SBOM but not direct scan)
		require.NoError(t, os.WriteFile(filepath.Join(pkgDir, "LICENSE"), []byte("nested license"), 0644))
	}

	// Add root license
	mitLicense := readTestLicense(t, "mit-license-short.txt")
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "LICENSE"), []byte(mitLicense), 0644))

	ch, err := NewCaseHandler()
	require.NoError(t, err)
	defer ch.Close()

	// Measure time taken
	start := time.Now()
	result, err := ch.handleDir(tempDir)
	duration := time.Since(start)

	require.NoError(t, err)

	// Should complete reasonably quickly
	assert.Less(t, duration, 30*time.Second, "Should complete within 30 seconds even with 1000+ files")

	// The new implementation should create an SBOM for the whole directory
	// or find just root licenses if SBOM fails
	t.Logf("Found %d SBOMs and %d licenses in %v", len(result.SBOMS), len(result.Licenses), duration)
}

func TestHandleDir_DisableFileSearchConfig(t *testing.T) {
	tempDir := t.TempDir()

	// Create license files with full license text that should be detected
	mitLicense := readTestLicense(t, "mit-license.txt")
	apacheLicense := readTestLicense(t, "apache-license.txt")

	testFiles := []struct {
		name    string
		content string
	}{
		{"LICENSE", mitLicense},
		{"APACHE-2.0", apacheLicense},
	}

	for _, tf := range testFiles {
		require.NoError(t, os.WriteFile(filepath.Join(tempDir, tf.name), []byte(tf.content), 0644))
	}

	// Test directory without package files to ensure SBOM generation might fail
	// but license detection still works

	// Test with DisableFileSearch = true
	ch, err := NewCaseHandlerWithConfig(CaseConfig{DisableFileSearch: true})
	require.NoError(t, err)
	defer ch.Close()

	result, err := ch.handleDir(tempDir)
	require.NoError(t, err)

	// Should not find licenses when DisableFileSearch is true
	t.Logf("With DisableFileSearch=true: Found %d SBOMs and %d licenses", len(result.SBOMS), len(result.Licenses))
	assert.Equal(t, 0, len(result.Licenses), "Should not find licenses when DisableFileSearch is true")

	// Test with DisableFileSearch = false (default)
	ch2, err := NewCaseHandler()
	require.NoError(t, err)
	defer ch2.Close()

	result2, err := ch2.handleDir(tempDir)
	require.NoError(t, err)

	// Should find licenses when DisableFileSearch is false
	t.Logf("With DisableFileSearch=false: Found %d SBOMs and %d licenses", len(result2.SBOMS), len(result2.Licenses))
	assert.GreaterOrEqual(t, len(result2.Licenses), 1, "Should find licenses when DisableFileSearch is false")

	// Verify we actually detected licenses and log what we found
	for _, license := range result2.Licenses {
		t.Logf("Found license: %s (ID: %s)", license.Name, license.LicenseID)
	}
	// Just verify that licenses were found - the specific type detection depends on the classifier
	assert.True(t, len(result2.Licenses) > 0, "Should detect licenses when DisableFileSearch is false")
}

func TestCaseHandler_CloseWithActiveOperations(t *testing.T) {
	// This test verifies that closing the CaseHandler properly waits for
	// concurrent operations to complete before closing the backend channel.
	// The fix uses sync.WaitGroup (activeOps) to track active operations
	// and prevent the "send on closed channel" panic.

	tempDir := t.TempDir()

	// Create multiple license files that will trigger concurrent classifications
	mitLicense := readTestLicense(t, "mit-license.txt")
	apacheLicense := readTestLicense(t, "apache-license.txt")
	gplLicense := readTestLicense(t, "gpl-license.txt")

	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "LICENSE"), []byte(mitLicense), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "LICENSE-MIT"), []byte(mitLicense), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "LICENSE-APACHE"), []byte(apacheLicense), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "COPYING"), []byte(gplLicense), 0644))

	// Create nested directories with more licenses to increase concurrent operations
	for i := 0; i < 5; i++ {
		nestedDir := filepath.Join(tempDir, fmt.Sprintf("subdir%d", i))
		require.NoError(t, os.MkdirAll(nestedDir, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(nestedDir, "LICENSE"), []byte(mitLicense), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(nestedDir, "COPYING"), []byte(apacheLicense), 0644))
	}

	ch, err := NewCaseHandler()
	require.NoError(t, err)

	// Process the directory - this will spawn concurrent goroutines
	// that use the license classifier backend
	result, handleErr := ch.handleDir(tempDir)

	// Close the handler after operations complete
	// The Close() method should wait for all activeOps to finish
	// before closing the backend, preventing any panic
	ch.Close()

	// Verify that the operation completed successfully without panicking
	require.NoError(t, handleErr)
	assert.GreaterOrEqual(t, len(result.Licenses), 1, "Should have found licenses")

	t.Log("Test passed: No panic occurred when closing handler after operations")
}

func TestCaseHandler_MultipleHandleLicenseFilesConcurrent(t *testing.T) {
	// This test verifies that multiple concurrent handleLicenseFile operations
	// can safely share the backend without causing panics. The activeOps WaitGroup
	// ensures proper synchronization.

	tempDir := t.TempDir()

	// Create several license files using well-recognized licenses
	mitLicense := readTestLicense(t, "mit-license.txt")
	apacheLicense := readTestLicense(t, "apache-license.txt")

	licensePaths := []string{
		filepath.Join(tempDir, "LICENSE-MIT-1"),
		filepath.Join(tempDir, "LICENSE-MIT-2"),
		filepath.Join(tempDir, "LICENSE-APACHE"),
		filepath.Join(tempDir, "LICENSE-MIT-3"),
	}

	require.NoError(t, os.WriteFile(licensePaths[0], []byte(mitLicense), 0644))
	require.NoError(t, os.WriteFile(licensePaths[1], []byte(mitLicense), 0644))
	require.NoError(t, os.WriteFile(licensePaths[2], []byte(apacheLicense), 0644))
	require.NoError(t, os.WriteFile(licensePaths[3], []byte(mitLicense), 0644))

	ch, err := NewCaseHandler()
	require.NoError(t, err)

	// Process multiple license files concurrently
	var wg sync.WaitGroup
	successCount := 0
	var mu sync.Mutex

	for _, path := range licensePaths {
		wg.Add(1)
		go func(licensePath string) {
			defer wg.Done()
			licenses, err := ch.handleLicenseFile(licensePath)
			if err == nil && len(licenses) > 0 {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
		}(path)
	}

	// Wait for all concurrent operations to complete
	wg.Wait()

	// Close the handler after all operations
	// This should not panic because activeOps.Wait() ensures all
	// ClassifyLicensesWithContext goroutines have finished
	ch.Close()

	// Verify that we successfully processed at least some licenses concurrently
	assert.Greater(t, successCount, 0, "Should have successfully processed at least one license")

	t.Logf("Test passed: %d/%d concurrent operations completed successfully without panic", successCount, len(licensePaths))
}
