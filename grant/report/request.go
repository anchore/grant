package report

import (
	"fmt"
	"io"
	"os"

	"github.com/google/licenseclassifier/v2/tools/identify_license/results"

	"github.com/anchore/grant/grant"
	"github.com/anchore/grant/internal"
	"github.com/anchore/grant/internal/log"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

type RequestID string

type Request struct {
	RequestID RequestID

	// UserInput is the user input that was broken down into different Evaluations
	// can be something like ./; so it can contain multiple Evaluations
	// Consider: ./foo.spdx ./MIT ./image.tar.gz
	// The UserInput in the above case would be "./" and the Evaluations would be:
	// - ./foo.spdx SBOM
	// - ./MIT LICENSE
	// - ./image.tar.gz Generated SBOM
	UserInput string

	// Evaluation is a pass/fail for the entire request;
	Evaluations []Evaluation
}

// NewRequest will generate a new request for the given userInput
// The policy is applied to each determined Evaluation
// A valid userRequest can be:
// - a path to an SBOM file
// - a path to a license
// - a path to an archive
// - a path to a directory (with any of the above)
// - or some container image
func NewRequest(userInput string, p grant.Policy) Request {
	evaluations := make([]Evaluation, 0)
	// TODO: we need to inject the user config here and convert it into a evaluation config
	ec := EvaluationConfig{Policy: p}
	requestBreakdown, err := determineRequest(userInput)
	if err != nil {
		log.Errorf("unable to determine SBOM or licenses for %s: %+v", userInput, err)
	}

	// results are broken down into SBOMs (pkg -> license)
	// or raw licenses that were detected with no package association
	for _, sb := range requestBreakdown.sboms {
		evaluations = append(evaluations, NewEvaluationFromSBOM(ec, sb))
	}

	for _, license := range requestBreakdown.licenses {
		evaluations = append(evaluations, NewEvaluationFromLicense(ec, license))
	}

	// TODO: generate stable request ID
	return Request{
		RequestID:   "",
		UserInput:   userInput,
		Evaluations: evaluations,
	}
}

// easy way to break down a user request into SBOMs (generated or passed) and discovered licenses
type requestBreakdown struct {
	sboms    []sbom.SBOM     // All SBOMs found for the user request
	licenses []grant.License // All licenses found for the user request (can be a directory of licenses or if the user request is a license)
}

// A valid userRequest can be:
// - a path to an SBOM file
// - a path to a license
// - a path to a directory
// - a path to an archive
// - a path to a directory (with any of the above)
// - a container image (ubuntu:latest)
func determineRequest(userRequest string) (r *requestBreakdown, err error) {
	switch {
	case isFile(userRequest):
		return handleFile(userRequest)
	case isDirectory(userRequest):
		return handleDir(userRequest)
	default:
		return handleContainer(userRequest)
	}

	// alright you got us here, we don't know what to do with this
	return nil, fmt.Errorf("unable to determine SBOM or licenses for %s", userRequest)
}

// TODO: is the default syft config good enough here?
// we definitely need at least all the non default license magic turned on
func generateSyftSBOM(path string) (sb sbom.SBOM, err error) {
	detection, err := source.Detect("alpine:latest", source.DefaultDetectConfig())
	if err != nil {
		return sb, err
	}

	src, err := detection.NewSource(source.DefaultDetectionSourceConfig())
	if err != nil {
		return sb, err
	}
	collection, relationships, release, err := syft.CatalogPackages(src, cataloger.DefaultConfig())
	if err != nil {
		return sb, err
	}

	sb = sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages:          collection,
			LinuxDistribution: release,
		},
		Relationships: relationships,
		Source:        src.Describe(),
		Descriptor: sbom.Descriptor{
			Name:    internal.ApplicationName,
			Version: internal.ApplicationVersion,
		},
	}
	return sb, nil
}

func getReadSeeker(path string) (io.ReadSeeker, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open file: %w", err)
	}
	return file, nil
}

func grantLicenseFromClassifierResults(r results.LicenseTypes) []grant.License {
	licenses := make([]grant.License, 0)
	for _, license := range r {
		// TODO: the license classifier gives us more information than just the name
		if license.MatchType == "License" {
			licenses = append(licenses, grant.License{
				Name: license.Name,
			})
		}
	}
	return licenses
}
