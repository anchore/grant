package grant

import (
	"strings"

	syftPkg "github.com/anchore/syft/syft/pkg"
)

// PackageID is a unique identifier for a package that is tracked by grant
// It's usually provided by the SBOM; It's calculated if an SBOM is generated
type PackageID string

// Package is a package that is tracked by grant
// These packages are decoded from SBOMs: spdx, cyclonedx, syft
type Package struct {
	ID        PackageID `json:"id" yaml:"id"`
	Name      string    `json:"name" yaml:"name"`
	Type      string    `json:"type" yaml:"type"`
	Version   string    `json:"version" yaml:"version"`
	Licenses  []License `json:"licenses" yaml:"licenses"`
	Locations []string  `json:"locations" yaml:"locations"`
}

func ConvertSyftPackage(p syftPkg.Package) *Package {
	locations := p.Locations.ToSlice()
	packageLocations := make([]string, 0)
	for _, location := range locations {
		packageLocations = append(packageLocations, location.RealPath)
	}

	return &Package{
		Name:      packageNameFromSyft(p),
		Version:   p.Version,
		Type:      string(p.Type),
		Licenses:  ConvertSyftLicenses(p.Licenses),
		Locations: packageLocations,
	}
}

func packageNameFromSyft(p syftPkg.Package) string {
	name := p.Name

	switch metadata := p.Metadata.(type) {
	case syftPkg.JavaArchive:
		return packageNameFromJavaMetadata(name, metadata.PomProperties)
	case *syftPkg.JavaArchive:
		if metadata != nil {
			return packageNameFromJavaMetadata(name, metadata.PomProperties)
		}
	}

	return name
}

func packageNameFromJavaMetadata(name string, pomProperties *syftPkg.JavaPomProperties) string {
	groupID := ""
	if pomProperties != nil {
		groupID = strings.TrimSpace(pomProperties.GroupID)
	}
	if groupID == "" || name == "" || name == groupID || strings.HasPrefix(name, groupID+".") {
		return name
	}

	return groupID + "." + name
}
