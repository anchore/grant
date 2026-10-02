package grant

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/licenseclassifier/v2/assets"
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
	for i := range 100 {
		pkgDir := filepath.Join(tempDir, "node_modules", fmt.Sprintf("package%d", i))
		require.NoError(t, os.MkdirAll(pkgDir, 0755))

		// Create 10 files in each package
		for j := range 10 {
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

func TestSearchLicenseFiles_Symlinks(t *testing.T) {
	// writeLicense writes an MIT license at dir/rel, creating parent dirs
	writeLicense := func(t *testing.T, dir, rel string) {
		t.Helper()
		p := filepath.Join(dir, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0755))
		require.NoError(t, os.WriteFile(p, []byte(readTestLicense(t, "mit-license.txt")), 0644))
	}

	// each case holds a single license file at most: the classifier backend accumulates
	// results across calls, so more files would inflate the count
	tests := []struct {
		name string
		// setup builds the tree under dir and returns the path to scan
		setup func(t *testing.T, dir string) string
		want  int
	}{
		{
			name: "follows symlinked scan root",
			setup: func(t *testing.T, dir string) string {
				writeLicense(t, dir, "real/LICENSE")
				require.NoError(t, os.Symlink("real", filepath.Join(dir, "link")))
				return filepath.Join(dir, "link")
			},
			want: 1,
		},
		{
			name: "follows symlink to directory that is otherwise skipped",
			setup: func(t *testing.T, dir string) string {
				// mimics snap package layout (e.g. libncursesw6 -> libtinfo6/), with the
				// target under a skip-listed dir so it is only reachable through the link
				writeLicense(t, dir, "vendor/libtinfo6/LICENSE")
				require.NoError(t, os.Symlink("vendor/libtinfo6", filepath.Join(dir, "libncursesw6")))
				return dir
			},
			want: 1,
		},
		{
			name: "follows symlink whose target name is skip-listed",
			setup: func(t *testing.T, dir string) string {
				writeLicense(t, dir, "vendor/build/LICENSE")
				require.NoError(t, os.Symlink("vendor/build", filepath.Join(dir, "deps")))
				return dir
			},
			want: 1,
		},
		{
			name: "does not follow symlink whose own name is skip-listed",
			setup: func(t *testing.T, dir string) string {
				writeLicense(t, dir, "vendor/lib/LICENSE")
				require.NoError(t, os.Symlink("vendor/lib", filepath.Join(dir, "build")))
				return dir
			},
			want: 0,
		},
		{
			name: "dedupes license reachable directly and through symlinks",
			setup: func(t *testing.T, dir string) string {
				writeLicense(t, dir, "sub/LICENSE")
				require.NoError(t, os.Symlink("sub", filepath.Join(dir, "l1")))
				require.NoError(t, os.Symlink("sub", filepath.Join(dir, "l2")))
				return dir
			},
			want: 1,
		},
		{
			name: "terminates on symlink cycles",
			setup: func(t *testing.T, dir string) string {
				writeLicense(t, dir, "a/LICENSE")
				require.NoError(t, os.Symlink("..", filepath.Join(dir, "a", "loop")))
				require.NoError(t, os.Symlink("self", filepath.Join(dir, "self")))
				return dir
			},
			want: 1,
		},
		{
			name: "absolute symlink to directory resolves under the scan root",
			setup: func(t *testing.T, dir string) string {
				writeLicense(t, dir, "vendor/lib/LICENSE")
				require.NoError(t, os.Symlink("/vendor/lib", filepath.Join(dir, "lib")))
				return dir
			},
			want: 1,
		},
		{
			name: "absolute symlink to directory does not escape the scan root",
			setup: func(t *testing.T, dir string) string {
				outside := t.TempDir()
				writeLicense(t, outside, "LICENSE")
				require.NoError(t, os.Symlink(outside, filepath.Join(dir, "vendored")))
				return dir
			},
			want: 0,
		},
		{
			name: "relative symlink to directory does not escape the scan root",
			setup: func(t *testing.T, dir string) string {
				writeLicense(t, dir, "outside/LICENSE")
				require.NoError(t, os.MkdirAll(filepath.Join(dir, "root"), 0755))
				require.NoError(t, os.Symlink("../outside", filepath.Join(dir, "root", "vendored")))
				return filepath.Join(dir, "root")
			},
			want: 0,
		},
		{
			name: "follows symlink to file",
			setup: func(t *testing.T, dir string) string {
				writeLicense(t, dir, "actual-license.txt")
				require.NoError(t, os.Symlink("actual-license.txt", filepath.Join(dir, "LICENSE")))
				return dir
			},
			want: 1,
		},
		{
			name: "symlink to file does not escape the scan root",
			setup: func(t *testing.T, dir string) string {
				outside := t.TempDir()
				writeLicense(t, outside, "actual-license.txt")
				require.NoError(t, os.Symlink(filepath.Join(outside, "actual-license.txt"), filepath.Join(dir, "LICENSE")))
				return dir
			},
			want: 0,
		},
		{
			name: "skips broken symlink",
			setup: func(t *testing.T, dir string) string {
				require.NoError(t, os.Symlink("/nonexistent/target", filepath.Join(dir, "LICENSE")))
				writeLicense(t, dir, "COPYING")
				return dir
			},
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanPath := tt.setup(t, t.TempDir())

			ch, err := NewCaseHandler()
			require.NoError(t, err)
			defer ch.Close()

			licenses, err := ch.searchLicenseFiles(scanPath)
			require.NoError(t, err)
			assert.Len(t, licenses, tt.want)
		})
	}
}

// fullLicense writes a complete license text from the classifier's own assets to a
// temp file. The testdata fixtures are short snippets the classifier does not match.
func fullLicense(t *testing.T, asset string) string {
	t.Helper()
	b, err := assets.ReadLicenseFile(asset)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "LICENSE")
	require.NoError(t, os.WriteFile(path, b, 0o600))
	return path
}

func TestHandleLicenseFile_ResultsAreIndependent(t *testing.T) {
	ch, err := NewCaseHandler()
	require.NoError(t, err)
	defer ch.Close()

	ids := func(path string) []string {
		licenses, err := ch.handleLicenseFile(path)
		require.NoError(t, err)
		var out []string
		for _, l := range licenses {
			out = append(out, l.LicenseID)
		}
		return out
	}

	assert.Contains(t, ids(filepath.Join("testdata", "mit-license.txt")), "MIT")

	// the old backend never reset its results, so this also returned MIT
	apache := ids(fullLicense(t, "License/Apache-2.0/pristine.txt"))
	assert.Contains(t, apache, "Apache-2.0")
	assert.NotContains(t, apache, "MIT")
}

func TestHandleLicenseFile_Concurrent(t *testing.T) {
	ch, err := NewCaseHandler()
	require.NoError(t, err)
	defer ch.Close()

	// handleDir classifies concurrently; run with -race to check the classifier is guarded
	files := []string{
		filepath.Join("testdata", "mit-license.txt"),
		fullLicense(t, "License/Apache-2.0/pristine.txt"),
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		f := files[i%len(files)]
		wg.Go(func() {
			_, err := ch.handleLicenseFile(f)
			assert.NoError(t, err)
		})
	}
	wg.Wait()
}
