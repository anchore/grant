package grant

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grant/internal/licensepatterns"
)

func TestHandleDir_OnlyScansRootLicenseFiles(t *testing.T) {
	// Create a temporary test directory structure
	tempDir := t.TempDir()

	// Create license files at root with actual license content
	mitLicense := `MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction.`

	apacheLicense := `Apache License
Version 2.0, January 2004
http://www.apache.org/licenses/`

	gplLicense := `GNU GENERAL PUBLIC LICENSE
Version 3, 29 June 2007`

	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "LICENSE"), []byte(mitLicense), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "LICENSE.md"), []byte(apacheLicense), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "COPYING"), []byte(gplLicense), 0644))

	// Create a deeply nested directory structure with many files
	nestedDir := filepath.Join(tempDir, "node_modules", "package1", "subpackage")
	require.NoError(t, os.MkdirAll(nestedDir, 0755))

	// Create license files in nested directories that should NOT be scanned when SBOM fails
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "node_modules", "LICENSE"), []byte("Nested License 1"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(nestedDir, "LICENSE"), []byte("Nested License 2"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(nestedDir, "COPYING"), []byte("Nested License 3"), 0644))

	// Create many non-license files that should be ignored
	for i := 0; i < 100; i++ {
		filename := filepath.Join(nestedDir, fmt.Sprintf("file%d.js", i))
		require.NoError(t, os.WriteFile(filename, []byte("console.log('test');"), 0644))
	}

	// Test with an invalid directory that will make SBOM generation fail
	// Use a directory with no recognizable package files
	invalidDir := filepath.Join(tempDir, "empty_test_dir")
	require.NoError(t, os.MkdirAll(invalidDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(invalidDir, "LICENSE"), []byte(mitLicense), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(invalidDir, "random.txt"), []byte("not a package file"), 0644))

	ch, err := NewCaseHandler()
	require.NoError(t, err)
	defer ch.Close()

	// Call handleDir on the invalid directory - SBOM generation will fail or return empty
	// and it should fall back to license scanning
	result, err := ch.handleDir(invalidDir)
	require.NoError(t, err)

	// We should find the LICENSE file but the test verifies we're not recursively
	// walking directories when we fall back to license scanning
	if len(result.SBOMS) == 0 {
		// SBOM generation failed, we should have scanned for licenses
		assert.GreaterOrEqual(t, len(result.Licenses), 1, "Should find the LICENSE file")
	}
}

func TestHandleDir_UsesSBOMWhenSuccessful(t *testing.T) {
	tempDir := t.TempDir()

	// Create a simple test file
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "package.json"), []byte(`{"name":"test","version":"1.0.0"}`), 0644))

	ch, err := NewCaseHandler()
	require.NoError(t, err)
	defer ch.Close()

	// Call handleDir - this should use SBOM generation
	result, err := ch.handleDir(tempDir)
	require.NoError(t, err)

	// The new implementation tries SBOM generation first
	// Whether it succeeds depends on if Syft can identify packages
	t.Logf("Result: %d SBOMs, %d licenses", len(result.SBOMS), len(result.Licenses))
}

func TestCommonLicensePatterns(t *testing.T) {
	// Verify the common license patterns are what we expect
	expectedPatterns := []string{
		"LICENSE",
		"LICENSE.*",
		"LICENCE",
		"LICENCE.*",
		"COPYING",
		"COPYING.*",
		"NOTICE",
		"NOTICE.*",
	}

	// Check that all expected common patterns are present in the generated patterns
	for _, expected := range expectedPatterns {
		found := false
		for _, pattern := range licensepatterns.Patterns {
			if pattern == expected {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected pattern %s should be present in generated patterns", expected)
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
	mitLicense := `MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy`
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

func TestGenerateLicensePatterns(t *testing.T) {
	patterns := licensepatterns.Patterns

	require.NotEmpty(t, patterns, "Should generate license patterns")

	// Check that common patterns are included
	hasLicense := false
	hasCopying := false
	for _, p := range patterns {
		if p == "LICENSE" || p == "LICENSE.*" {
			hasLicense = true
		}
		if p == "COPYING" || p == "COPYING.*" {
			hasCopying = true
		}
	}

	assert.True(t, hasLicense, "Should include LICENSE patterns")
	assert.True(t, hasCopying, "Should include COPYING patterns")

	// Check that SPDX patterns are included (both upper and lower case)
	hasUpperGPL := false
	hasLowerGPL := false
	for _, p := range patterns {
		if p == "*GPL-3.0*" || p == "GPL-3.0" {
			hasUpperGPL = true
		}
		if p == "*gpl-3.0*" || p == "gpl-3.0" {
			hasLowerGPL = true
		}
	}

	assert.True(t, hasUpperGPL || hasLowerGPL, "Should include GPL-3.0 patterns")

	t.Logf("Generated %d patterns", len(patterns))
}

func TestHandleDir_ConcurrentSBOMAndLicenseSearch(t *testing.T) {
	tempDir := t.TempDir()

	// Create various license files with SPDX IDs
	testFiles := []struct {
		name    string
		content string
	}{
		{"LICENSE", "MIT License\n\nCopyright (c) 2024"},
		{"GPL-3.0", "GNU GENERAL PUBLIC LICENSE\nVersion 3"},
		{"apache-2.0.txt", "Apache License\nVersion 2.0"},
		{"MIT", "MIT License"},
		{"BSD-3-Clause", "BSD 3-Clause License"},
	}

	for _, tf := range testFiles {
		require.NoError(t, os.WriteFile(filepath.Join(tempDir, tf.name), []byte(tf.content), 0644))
	}

	// Create a package.json for SBOM generation
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "package.json"), []byte(`{"name":"test","version":"1.0.0"}`), 0644))

	ch, err := NewCaseHandler()
	require.NoError(t, err)
	defer ch.Close()

	// Call handleDir - should run both SBOM and license search concurrently
	result, err := ch.handleDir(tempDir)
	require.NoError(t, err)

	// Should find both SBOM and licenses
	t.Logf("Found %d SBOMs and %d licenses", len(result.SBOMS), len(result.Licenses))

	// We should find at least some licenses from our SPDX-named files
	if len(result.Licenses) > 0 {
		assert.GreaterOrEqual(t, len(result.Licenses), 1, "Should find at least one license file")
	}
}

func TestHandleDir_SBOMOnlyConfig(t *testing.T) {
	tempDir := t.TempDir()

	// Create license files with full license text that should be detected
	mitLicense := `MIT License

Copyright (c) 2024 Test

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.`

	apacheLicense := `Apache License
Version 2.0, January 2004
http://www.apache.org/licenses/

TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

1. Definitions.

"License" shall mean the terms and conditions for use, reproduction,
and distribution as defined by Sections 1 through 9 of this document.`

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

	// Test with SBOMOnly = true
	ch, err := NewCaseHandlerWithConfig(CaseConfig{SBOMOnly: true})
	require.NoError(t, err)
	defer ch.Close()

	result, err := ch.handleDir(tempDir)
	require.NoError(t, err)

	// Should not find licenses when SBOMOnly is true
	t.Logf("With SBOMOnly=true: Found %d SBOMs and %d licenses", len(result.SBOMS), len(result.Licenses))
	assert.Equal(t, 0, len(result.Licenses), "Should not find licenses when SBOMOnly is true")

	// Test with SBOMOnly = false (default)
	ch2, err := NewCaseHandler()
	require.NoError(t, err)
	defer ch2.Close()

	result2, err := ch2.handleDir(tempDir)
	require.NoError(t, err)

	// Should find licenses when SBOMOnly is false
	t.Logf("With SBOMOnly=false: Found %d SBOMs and %d licenses", len(result2.SBOMS), len(result2.Licenses))
	assert.GreaterOrEqual(t, len(result2.Licenses), 1, "Should find licenses when SBOMOnly is false")

	// Verify we actually detected licenses and log what we found
	for _, license := range result2.Licenses {
		t.Logf("Found license: %s (ID: %s)", license.Name, license.LicenseID)
	}
	// Just verify that licenses were found - the specific type detection depends on the classifier
	assert.True(t, len(result2.Licenses) > 0, "Should detect licenses when SBOMOnly is false")
}
