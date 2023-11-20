//go:generate go run generate_license_index.go
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/anchore/grant/internal/spdxlicense"
)

const (
	generates = "../license_index.go"
	// TODO: should we pull from other sources like the github api?
	url = "https://spdx.org/licenses/licenses.json"
)

var FuncMap = template.FuncMap{
	"ToLower": func(format string, args ...interface{}) string {
		return strings.ToLower(fmt.Sprintf(format, args...))
	},
}

var codeTemplate = template.Must(template.New("license_index.go").Funcs(FuncMap).Parse(`// Code generated by internal/spdxlicense/generate/generate_license_index.go; DO NOT EDIT.
// This file was generated by go generate; DO NOT EDIT; {{ .Timestamp }}
// License source: {{ .URL }}
package spdxlicense

const Version = {{ printf "%q" .Version }}

const ReleaseData = {{ printf "%q" .ReleaseDate }}

var Index = map[string]SPDXLicense{
{{- range .Licenses }}
	{{ ToLower "%q" .LicenseID }}: {
		Reference: {{ printf "%q" .Reference }},
		IsDeprecatedLicenseID: {{ .IsDeprecatedLicenseID }},
		DetailsURL: {{ printf "%q" .DetailsURL }},
		ReferenceNumber: {{ .ReferenceNumber }},
		Name: {{ printf "%q" .Name }},
		LicenseID: {{ printf "%q" .LicenseID }},
		SeeAlso: []string{
			{{- range .SeeAlso }}
			{{ printf "%q" . }},
			{{- end }}	
		},	
		IsOsiApproved: {{ .IsOsiApproved }},
	},
{{- end }}
}
`))

func main() {
	if err := generate(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("generated", generates)
}

func generate() error {
	spdxLicenseResposne, err := fetchLicenses(url)
	if err != nil {
		return err
	}

	if err := os.Remove(generates); err != nil && !os.IsNotExist(err) {
		fmt.Println("Error deleting existing file:", err)
		return err
	}

	f, err := os.Create(generates)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := codeTemplate.Execute(f, struct {
		Timestamp   string
		URL         string
		Version     string
		ReleaseDate string
		Licenses    []spdxlicense.SPDXLicense
	}{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		URL:         url,
		Version:     spdxLicenseResposne.LicenseListVersion,
		ReleaseDate: spdxLicenseResposne.ReleaseDate,
		Licenses:    spdxLicenseResposne.Licenses,
	}); err != nil {
		return err
	}
	return nil
}

func fetchLicenses(url string) (r *spdxlicense.SPDXLicenseResponse, err error) {
	response, err := http.Get(url)
	if err != nil {
		return r, err
	}
	defer response.Body.Close()
	var spdxLicenseResponse spdxlicense.SPDXLicenseResponse
	if err := json.NewDecoder(response.Body).Decode(&spdxLicenseResponse); err != nil {
		return r, err
	}
	return &spdxLicenseResponse, nil
}
