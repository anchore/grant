package grant

import syftpkg "github.com/anchore/syft/syft/pkg"

// Package is a single package that is tracked by grant
type Package struct {
	Name      string    `json:"name" yaml:"name"`
	Version   string    `json:"version" yaml:"version"`
	Source    string    `json:"source" yaml:"source"`
	Licenses  []License `json:"licenses" yaml:"licenses"`
	Locations []string  `json:"locations" yaml:"locations"`
}

func ConvertSyftPackage(p syftpkg.Package, source string) Package {
	locations := p.Locations.ToSlice()
	packageLocations := make([]string, 0)
	for _, location := range locations {
		packageLocations = append(packageLocations, location.RealPath)
	}

	return Package{
		Name:      p.Name,
		Version:   p.Version,
		Source:    source,
		Licenses:  ConvertSyftLicenses(p.Licenses),
		Locations: packageLocations,
	}
}
