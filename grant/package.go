package grant

import syftPkg "github.com/anchore/syft/syft/pkg"

// PackageID is a unique identifier for a package that is tracked by grant
// It's usually provided by the SBOM; It's calculated if an SBOM is generated
type PackageID string

// Package is a single package that is tracked by grant
type Package struct {
	ID        PackageID `json:"id" yaml:"id"`
	Name      string    `json:"name" yaml:"name"`
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
		Name:      p.Name,
		Version:   p.Version,
		Licenses:  ConvertSyftLicenses(p.Licenses),
		Locations: packageLocations,
	}
}
