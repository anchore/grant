package report

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	golog "log"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/licenseclassifier/v2/tools/identify_license/backend"

	"github.com/anchore/grant/grant"
	"github.com/anchore/grant/internal"
	"github.com/anchore/grant/internal/log"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func handleFile(path string) (r *requestBreakdown, err error) {
	// let's see if it's an archive (isArchive)
	if isArchive(path) {
		sb, err := generateSyftSBOM(path)
		if err != nil {
			// We bail here since we can't generate an SBOM for the archive
			return nil, err
		}

		// if there are licenses in the archive, syft should be enhanced to include them in the SBOM
		// this overlap is a little weird, but grant should be able to take license files as input
		return &requestBreakdown{
			sboms:    []sbom.SBOM{sb},
			licenses: make([]grant.License, 0),
		}, nil
	}

	// let's see if it's an SBOM
	bytes, err := getReadSeeker(path)
	if err != nil {
		// We bail here since we can't get a reader for the file
		return nil, err
	}

	sb, _, _, err := format.NewDecoderCollection(format.Decoders()...).Decode(bytes)
	if sb != nil {
		return &requestBreakdown{
			sboms:    []sbom.SBOM{*sb},
			licenses: make([]grant.License, 0),
		}, nil
	}
	// TODO: some log for the error here?

	// alright we couldn't get an SBOM, let's see if the bytes are just a LICENSE (google license classifier)
	be, err := backend.New()
	if err != nil {
		return nil, err
	}
	defer be.Close()

	// google license classifier is noisy, so we'll silence it for now
	golog.SetOutput(io.Discard)
	if errs := be.ClassifyLicensesWithContext(
		context.Background(),
		1000,
		[]string{path},
		false,
	); errs != nil {
		be.Close()
		for _, err := range errs {
			log.Errorf("unable to classify license: %+v", err)
		}
		return nil, fmt.Errorf("unable to classify license: %+v", err)
	}
	// re-enable logging for the rest of the application
	golog.SetOutput(os.Stdout)

	results := be.GetResults()
	if len(results) == 0 {
		return nil, fmt.Errorf("unable to determine SBOM or licenses for %s", path)
	}

	licenses := grantLicenseFromClassifierResults(results)

	return &requestBreakdown{
		sboms:    make([]sbom.SBOM, 0),
		licenses: licenses,
	}, nil
}

func handleDir(root string) (r *requestBreakdown, err error) {
	totalBreakdown := &requestBreakdown{
		sboms:    make([]sbom.SBOM, 0),
		licenses: make([]grant.License, 0),
	}

	// Define the closure that will be used as the visit function
	visit := func(s string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			// This isn't broken, the license classifier just returned two licenses
			r, err := handleFile(s)
			if err != nil {
				// TODO: some log for the error here?
				return nil
			}
			totalBreakdown.sboms = append(totalBreakdown.sboms, r.sboms...)
			totalBreakdown.licenses = append(totalBreakdown.licenses, r.licenses...)
		}
		return nil
	}

	err = filepath.WalkDir(root, visit)
	if err != nil {
		return nil, err
	}
	return totalBreakdown, nil
}

func handleContainer(image string) (r *requestBreakdown, err error) {
	detection, err := source.Detect("alpine:latest", source.DefaultDetectConfig())
	if err != nil {
		return nil, err
	}

	src, err := detection.NewSource(source.DefaultDetectionSourceConfig())
	if err != nil {
		return nil, err
	}

	collection, relationships, release, err := syft.CatalogPackages(src, cataloger.DefaultConfig())
	if err != nil {
		return nil, err
	}

	sb := sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages:          collection,
			LinuxDistribution: release,
		},
		Relationships: relationships,
		Source:        src.Describe(),
		Descriptor: sbom.Descriptor{
			Name:    internal.ApplicationName, // Your Program rather than syft
			Version: internal.ApplicationVersion,
			// the application configuration can be persisted here
			Configuration: map[string]string{
				"config-key": "config-value",
			},
		},
	}

	return &requestBreakdown{
		sboms:    []sbom.SBOM{sb},
		licenses: make([]grant.License, 0),
	}, nil
}

func isDirectory(path string) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		log.Errorf("unable to stat directory %s: %+v", path, err)
		return false
	}
	return fileInfo.IsDir()
}

func isArchive(path string) bool {
	extension := filepath.Ext(path)
	archiveExtensions := []string{".zip", ".tar", ".gz", ".rar", ".7z"}

	for _, archiveExtension := range archiveExtensions {
		if strings.EqualFold(extension, archiveExtension) {
			return true
		}
	}

	return false
}

func isFile(path string) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		log.Errorf("unable to stat file %s: %+v", path, err)
		return false
	}
	return !fileInfo.IsDir()
}
