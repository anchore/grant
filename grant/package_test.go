package grant

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
)

func TestConvertSyftPackage_MavenGroup(t *testing.T) {
	tests := []struct {
		name          string
		syftPkg       pkg.Package
		expectedName  string
		expectedGroup string
	}{
		{
			name: "reads the group from pom properties",
			syftPkg: pkg.Package{
				Name:    "slf4j-api",
				Version: "2.0.17",
				Type:    pkg.JavaPkg,
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{GroupID: "org.slf4j"},
				},
			},
			expectedName:  "slf4j-api",
			expectedGroup: "org.slf4j",
		},
		{
			name: "falls back to the pom project group",
			syftPkg: pkg.Package{
				Name:    "commons-text",
				Version: "1.10.0",
				Type:    pkg.JavaPkg,
				Metadata: pkg.JavaArchive{
					PomProject: &pkg.JavaPomProject{GroupID: "org.apache.commons", ArtifactID: "commons-text"},
				},
			},
			expectedName:  "commons-text",
			expectedGroup: "org.apache.commons",
		},
		{
			name: "prefers the pom properties group over the pom project group",
			syftPkg: pkg.Package{
				Name:    "commons-text",
				Version: "1.10.0",
				Type:    pkg.JavaPkg,
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{GroupID: "org.apache.commons"},
					PomProject:    &pkg.JavaPomProject{GroupID: "org.apache.commons.shaded"},
				},
			},
			expectedName:  "commons-text",
			expectedGroup: "org.apache.commons",
		},
		{
			name: "reads java metadata by pointer",
			syftPkg: pkg.Package{
				Name:    "slf4j-api",
				Version: "2.0.17",
				Type:    pkg.JavaPkg,
				Metadata: &pkg.JavaArchive{
					PomProject: &pkg.JavaPomProject{GroupID: "org.slf4j"},
				},
			},
			expectedName:  "slf4j-api",
			expectedGroup: "org.slf4j",
		},
		{
			name: "falls back to the purl when the sbom dropped the pom metadata",
			syftPkg: pkg.Package{
				Name:     "slf4j-api",
				Version:  "2.0.17",
				Type:     pkg.JavaPkg,
				PURL:     "pkg:maven/org.slf4j/slf4j-api@2.0.17",
				Metadata: pkg.JavaArchive{},
			},
			expectedName:  "slf4j-api",
			expectedGroup: "org.slf4j",
		},
		{
			name: "falls back to the purl when there is no java metadata at all",
			syftPkg: pkg.Package{
				Name:    "slf4j-api",
				Version: "2.0.17",
				Type:    pkg.JavaPkg,
				PURL:    "pkg:maven/org.slf4j/slf4j-api@2.0.17",
			},
			expectedName:  "slf4j-api",
			expectedGroup: "org.slf4j",
		},
		{
			name: "prefers the pom metadata over the purl",
			syftPkg: pkg.Package{
				Name:    "slf4j-api",
				Version: "2.0.17",
				Type:    pkg.JavaPkg,
				PURL:    "pkg:maven/org.slf4j.shaded/slf4j-api@2.0.17",
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{GroupID: "org.slf4j"},
				},
			},
			expectedName:  "slf4j-api",
			expectedGroup: "org.slf4j",
		},
		{
			name: "ignores a non-maven purl",
			syftPkg: pkg.Package{
				Name:     "some-shaded-jar",
				Version:  "1.0.0",
				Type:     pkg.JavaPkg,
				PURL:     "pkg:generic/some-shaded-jar@1.0.0",
				Metadata: pkg.JavaArchive{},
			},
			expectedName:  "some-shaded-jar",
			expectedGroup: "",
		},
		{
			name: "leaves java packages without a group unqualified",
			syftPkg: pkg.Package{
				Name:     "some-shaded-jar",
				Version:  "1.0.0",
				Type:     pkg.JavaPkg,
				Metadata: pkg.JavaArchive{PomProperties: &pkg.JavaPomProperties{}},
			},
			expectedName:  "some-shaded-jar",
			expectedGroup: "",
		},
		{
			name: "does not repeat a name that is already the group",
			syftPkg: pkg.Package{
				Name:    "org.slf4j",
				Version: "2.0.17",
				Type:    pkg.JavaPkg,
				Metadata: pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{GroupID: "org.slf4j"},
				},
			},
			expectedName:  "org.slf4j",
			expectedGroup: "",
		},
		{
			name: "leaves non-java packages ungrouped",
			syftPkg: pkg.Package{
				Name:    "requests",
				Version: "2.32.3",
				Type:    pkg.PythonPkg,
				PURL:    "pkg:pypi/requests@2.32.3",
			},
			expectedName:  "requests",
			expectedGroup: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			converted := ConvertSyftPackage(tt.syftPkg)
			assert.Equal(t, tt.expectedName, converted.Name, "name must stay exactly as the sbom reports it")
			assert.Equal(t, tt.expectedGroup, converted.Group)
		})
	}
}

func TestPackageCoordinate(t *testing.T) {
	assert.Equal(t, "org.slf4j:slf4j-api", Package{Group: "org.slf4j", Name: "slf4j-api"}.Coordinate())
	assert.Equal(t, "requests", Package{Name: "requests"}.Coordinate())
}

func TestMergeDuplicatePackages_KeepsDistinctGroupsSeparate(t *testing.T) {
	packages := []Package{
		{Name: "core", Group: "com.foo", Version: "1.0.0", Type: "java-archive"},
		{Name: "core", Group: "com.bar", Version: "1.0.0", Type: "java-archive"},
	}

	merged := mergeDuplicatePackages(nil, packages)

	assert.Len(t, merged, 2, "same artifact id under different groups must not be merged")
}

func TestPolicyIsPackageIgnored_MatchesNameOrCoordinate(t *testing.T) {
	pkg := Package{Name: "core", Group: "com.foo", Version: "1.0.0", Type: "java-archive"}

	assert.True(t, (&Policy{IgnorePackages: []string{"core"}}).isPackageIgnored(pkg),
		"an existing bare-name pattern must keep matching")
	assert.True(t, (&Policy{IgnorePackages: []string{"com.foo:core"}}).isPackageIgnored(pkg),
		"a group-qualified pattern should match")
	assert.False(t, (&Policy{IgnorePackages: []string{"com.bar:core"}}).isPackageIgnored(pkg),
		"a pattern for another group should not match")
}
