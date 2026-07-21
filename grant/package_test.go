package grant

import (
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/assert"
)

func TestConvertSyftPackage_UsesMavenGroupIDInName(t *testing.T) {
	tests := []struct {
		name     string
		syftPkg  pkg.Package
		expected string
	}{
		{
			name: "prefixes java package name with pom group id",
			syftPkg: pkg.Package{
				Name:    "slf4j-api",
				Version: "2.0.17",
				Type:    pkg.JavaPkg,
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{GroupID: "org.slf4j"},
				},
			},
			expected: "org.slf4j.slf4j-api",
		},
		{
			name: "does not double-prefix a name already including the group id",
			syftPkg: pkg.Package{
				Name:    "org.slf4j.slf4j-api",
				Version: "2.0.17",
				Type:    pkg.JavaPkg,
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{GroupID: "org.slf4j"},
				},
			},
			expected: "org.slf4j.slf4j-api",
		},
		{
			name: "leaves non-java package names unchanged",
			syftPkg: pkg.Package{
				Name:    "requests",
				Version: "2.32.3",
				Type:    pkg.PythonPkg,
			},
			expected: "requests",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			converted := ConvertSyftPackage(tt.syftPkg)
			assert.Equal(t, tt.expected, converted.Name)
		})
	}
}
