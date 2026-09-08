package grant

import (
	"strings"

	"github.com/anchore/packageurl-go"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// PackageID is a unique identifier for a package that is tracked by grant
// It's usually provided by the SBOM; It's calculated if an SBOM is generated
type PackageID string

// Package is a package that is tracked by grant
// These packages are decoded from SBOMs: spdx, cyclonedx, syft
type Package struct {
	ID PackageID `json:"id" yaml:"id"`
	// Name is the package identity that policy and CLI filters match against, always exactly as
	// the SBOM reports it
	Name string `json:"name" yaml:"name"`
	// Group is the namespace that qualifies Name where the ecosystem has one (the maven group id
	// for java packages); it is empty for ecosystems without one
	Group     string    `json:"group,omitempty" yaml:"group,omitempty"`
	Type      string    `json:"type" yaml:"type"`
	Version   string    `json:"version" yaml:"version"`
	Licenses  []License `json:"licenses" yaml:"licenses"`
	Locations []string  `json:"locations" yaml:"locations"`
}

// QualifiedName is the fully qualified identity of a package, used to tell apart two packages that
// share a name under different groups. Name alone remains the matching identity.
func (p Package) QualifiedName() string {
	return qualifyName(p.Group, p.Name)
}

func qualifyName(group, name string) string {
	if group == "" {
		return name
	}

	return group + ":" + name
}

func ConvertSyftPackage(p syftPkg.Package) *Package {
	locations := p.Locations.ToSlice()
	packageLocations := make([]string, 0)
	for _, location := range locations {
		packageLocations = append(packageLocations, location.RealPath)
	}

	return &Package{
		Name:      p.Name,
		Group:     packageGroupFromSyft(p),
		Version:   p.Version,
		Type:      string(p.Type),
		Licenses:  ConvertSyftLicenses(p.Licenses),
		Locations: packageLocations,
	}
}

func packageGroupFromSyft(p syftPkg.Package) string {
	metadata, hasJavaMetadata := javaArchiveMetadata(p)
	if !hasJavaMetadata && p.Type != syftPkg.JavaPkg {
		return ""
	}

	groupID := javaGroupID(metadata, mavenPURL(p.PURL))
	if groupID == p.Name {
		return ""
	}

	return groupID
}

func javaArchiveMetadata(p syftPkg.Package) (syftPkg.JavaArchive, bool) {
	switch metadata := p.Metadata.(type) {
	case syftPkg.JavaArchive:
		return metadata, true
	case *syftPkg.JavaArchive:
		if metadata != nil {
			return *metadata, true
		}
	}

	return syftPkg.JavaArchive{}, false
}

// mavenPURL parses a maven purl, whose namespace and name are the group and artifact ids. SBOM
// formats that drop the pom metadata on decode still round-trip the purl, so it is the most
// widely available source of maven coordinates.
func mavenPURL(rawPURL string) packageurl.PackageURL {
	if rawPURL == "" {
		return packageurl.PackageURL{}
	}

	purl, err := packageurl.FromString(rawPURL)
	if err != nil || purl.Type != packageurl.TypeMaven {
		return packageurl.PackageURL{}
	}

	return purl
}

// javaGroupID returns the maven group id from whichever source carries it: archives with an
// embedded pom.properties populate PomProperties, the pom.xml and gradle lockfile catalogers
// populate PomProject, and decoded SBOMs may only have the purl.
func javaGroupID(metadata syftPkg.JavaArchive, purl packageurl.PackageURL) string {
	if metadata.PomProperties != nil {
		if groupID := strings.TrimSpace(metadata.PomProperties.GroupID); groupID != "" {
			return groupID
		}
	}

	if metadata.PomProject != nil {
		if groupID := strings.TrimSpace(metadata.PomProject.GroupID); groupID != "" {
			return groupID
		}
	}

	return strings.TrimSpace(purl.Namespace)
}
