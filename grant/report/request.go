package report

import (
	"fmt"
	"io"
	"os"

	"github.com/google/licenseclassifier/v2/tools/identify_license/results"

	"github.com/anchore/grant/grant"
	"github.com/anchore/grant/internal/log"
	"github.com/anchore/syft/syft/sbom"
)

type RequestID string

// Report
// userRequest
//
//	[]Evaluation}
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

	//// Evaluation is a pass/fail for the entire request;
	//Evalutations []Evaluation
}

// NewRequest will generate a new request for the given userInput
// The policy is applied to each determined Evaluation
// A valid userRequest can be:
// - a path to an SBOM file
// - a path to a license
// - a path to an archive
// - a path to a directory (with any of the above)
// - or some container image

// type Result []Evaluation
func NewRequest(userInput string, p grant.Policy) (r Request, err error) {
	determinations := make([]Determination, 0)

	// TODO: we need to inject the user config here and convert it into a evaluation config
	ec := EvaluationConfig{Policy: p}

	// Report contains requests
	requestBreakdown, err := determineRequest(userInput)
	if err != nil {
		log.Errorf("unable to determine SBOM or licenses for %s: %+v", userInput, err)
		return r, err
	}

	// results are broken down into SBOMs (pkg -> license)
	// or raw licenses that were detected with no package association
	for _, sb := range requestBreakdown.sboms {
		determinations = append(determinations, NewDeterminationFromSBOM(ec, sb))
	}

	for _, license := range requestBreakdown.licenses {
		determinations = append(determinations, NewDeterminationFromLicense(ec, license))
	}

	// TODO: generate stable request ID
	return Request{
		RequestID:      "",
		UserInput:      userInput,
		Determinations: determinations,
	}, nil
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
		// TODO: sometimes the license classifier gives us more information than just the name.
		// How do we want to handle this or include it in the grant.License?
		if license.MatchType == "License" {
			licenses = append(licenses, grant.License{
				Name: license.Name,
			})
		}
	}
	return licenses
}
