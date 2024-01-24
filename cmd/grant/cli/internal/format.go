package internal

import (
	"github.com/google/uuid"

	"github.com/anchore/grant/grant"
)

type Format string

const (
	JSON  Format = "json"
	Table Format = "table"
)

var ValidFormats = []Format{JSON, Table}

// ValidateFormat returns a valid format or the default format if the given format is invalid
func ValidateFormat(f Format) Format {
	switch f {
	case "json":
		return JSON
	case "table":
		return Table
	default:
		return Table
	}
}

func NewReportID() string {
	return uuid.Must(uuid.NewRandom()).String()
}

type License struct {
	SPDXExpression string   `json:"spdx_expression" yaml:"spdx_expression"`
	Name           string   `json:"name" yaml:"name"`
	Locations      []string `json:"locations" yaml:"locations"`
	Reference      string   `json:"reference" yaml:"reference"`
	IsDeprecated   bool     `json:"is_deprecated" yaml:"is_deprecated"`
	LicenseID      string   `json:"license_id" yaml:"license_id"`
	SeeAlso        []string `json:"see_also" yaml:"see_also"`
	IsOsiApproved  bool     `json:"is_osi_approved" yaml:"is_osi_approved"`
}

func NewLicense(l grant.License) License {
	return License{
		SPDXExpression: l.SPDXExpression,
		Name:           l.Name,
		Locations:      l.Locations,
		Reference:      l.Reference,
		IsDeprecated:   l.IsDeprecatedLicenseID,
		LicenseID:      l.LicenseID,
		SeeAlso:        l.SeeAlso,
		IsOsiApproved:  l.IsOsiApproved,
	}
}

type Package struct {
	Name      string   `json:"name" yaml:"name"`
	Version   string   `json:"version" yaml:"version"`
	Locations []string `json:"locations" yaml:"locations"`
}

func NewPackage(p *grant.Package) Package {
	if p == nil {
		return Package{}
	}
	return Package{
		Name:      p.Name,
		Version:   p.Version,
		Locations: p.Locations,
	}
}
