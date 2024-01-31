package grant

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	golog "log"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/licenseclassifier/v2/tools/identify_license/backend"
	"github.com/google/licenseclassifier/v2/tools/identify_license/results"

	"github.com/anchore/grant/internal/log"
	"github.com/anchore/grant/internal/spdxlicense"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/pkg/cataloger/golang"
	"github.com/anchore/syft/syft/pkg/cataloger/java"
	"github.com/anchore/syft/syft/pkg/cataloger/javascript"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// Case is a collection of SBOMs and Licenses that are evaluated for a given UserInput
type Case struct {
	// SBOMS is a list of SBOMs that were generated for the user input
	SBOMS []sbom.SBOM

	// Licenses is a list of licenses that were generated for the user input
	Licenses []License

	// UserInput is the string that was supplied by the user to build the case
	UserInput string
}

func NewCases(userInputs ...string) []Case {
	cases := make([]Case, 0)
	ch, err := NewCaseHandler()
	if err != nil {
		log.Errorf("unable to create case handler: %+v", err)
		return cases
	}
	defer ch.Close()
	for _, userInput := range userInputs {
		c, err := ch.determineRequestCase(userInput)
		if err != nil {
			log.Errorf("unable to determine case for %s: %+v", userInput, err)
			continue
		}
		c.UserInput = userInput
		cases = append(cases, c)
	}
	return cases
}

type Pair struct {
	License License
	Package *Package
}

func (c Case) GetLicenses() (map[string][]*Package, map[string]License, []Package) {
	licensePackages := make(map[string][]*Package)
	licenses := make(map[string]License)
	packagesNoLicenses := make([]Package, 0)
	for _, sb := range c.SBOMS {
		for pkg := range sb.Artifacts.Packages.Enumerate() {
			grantPkg := ConvertSyftPackage(pkg)
			// TODO: how do we express packages without licenses in list
			if len(grantPkg.Licenses) == 0 {
				packagesNoLicenses = append(packagesNoLicenses, *grantPkg)
				continue
			}
			buildLicenseMaps(licensePackages, licenses, grantPkg)
		}
	}

	return licensePackages, licenses, packagesNoLicenses
}

func buildLicenseMaps(licensePackages map[string][]*Package, licenses map[string]License, pkg *Package) {
	for _, license := range pkg.Licenses {
		if license.IsSPDX() {
			if _, ok := licenses[license.SPDXExpression]; !ok {
				licenses[license.SPDXExpression] = license
			}
			if _, ok := licensePackages[license.SPDXExpression]; !ok {
				licensePackages[license.SPDXExpression] = make([]*Package, 0)
			}
			licensePackages[license.SPDXExpression] = append(licensePackages[license.SPDXExpression], pkg)
			continue
		}

		// NonSPDX License
		if _, ok := licenses[license.Name]; !ok {
			licenses[license.Name] = license
		}
		if _, ok := licensePackages[license.Name]; !ok {
			licensePackages[license.Name] = make([]*Package, 0)
		}
		licensePackages[license.Name] = append(licensePackages[license.Name], pkg)
	}
}

type CaseHandler struct {
	Backend *backend.ClassifierBackend
}

func NewCaseHandler() (*CaseHandler, error) {
	be, err := backend.New()
	if err != nil {
		return &CaseHandler{}, err
	}
	return &CaseHandler{
		Backend: be,
	}, nil
}

func (ch *CaseHandler) Close() {
	ch.Backend.Close()
}

// A valid userRequest can be:
// - a path to an SBOM file
// - a path to a license
// - a path to a directory
// - a path to an archive
// - a path to a directory (with any of the above)
// - a container image (ubuntu:latest)
func (ch *CaseHandler) determineRequestCase(userRequest string) (c Case, err error) {
	switch {
	case isStdin(userRequest):
		return handleStdin()
	case isFile(userRequest):
		return ch.handleFile(userRequest)
	case isDirectory(userRequest):
		return ch.handleDir(userRequest)
	default:
		return handleContainer(userRequest)
	}
}

func handleStdin() (c Case, err error) {
	stdReader, err := decodeStdin(os.Stdin)
	if err != nil {
		return c, err
	}

	sb, _, _, err := format.NewDecoderCollection(format.Decoders()...).Decode(stdReader)
	if err != nil {
		return c, fmt.Errorf("unable to determine SBOM or licenses for stdin: %w", err)
	}
	if sb != nil {
		return Case{
			SBOMS:     []sbom.SBOM{*sb},
			Licenses:  make([]License, 0),
			UserInput: sb.Source.Name,
		}, nil
	}
	return c, fmt.Errorf("unable to determine SBOM or licenses for stdin")
}

func decodeStdin(r io.Reader) (io.ReadSeeker, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed reading stdin: %w", err)
	}

	reader := bytes.NewReader(b)
	_, err = reader.Seek(0, io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf("failed to parse stdin: %w", err)
	}

	return reader, nil
}

func (ch *CaseHandler) handleFile(path string) (c Case, err error) {
	// let's see if it's an archive (isArchive)
	if isArchive(path) {
		sb, err := generateSyftSBOM(path)
		if err != nil {
			// We bail here since we can't generate an SBOM for the archive
			return c, err
		}

		// if there are licenses in the archive, syft should be enhanced to include them in the SBOM
		// this overlap is a little weird, but grant should be able to take license files as input
		return Case{
			SBOMS:     []sbom.SBOM{sb},
			Licenses:  make([]License, 0),
			UserInput: path,
		}, nil
	}

	// let's see if it's an SBOM
	sbomBytes, err := getReadSeeker(path)
	if err != nil {
		// We bail here since we can't get a reader for the file
		return c, err
	}

	sb, _, _, err := format.NewDecoderCollection(format.Decoders()...).Decode(sbomBytes)
	if err != nil {
		log.Debugf("unable to determine SBOM or licenses for %s: %+v", path, err)
		// we want to log the error, but we don't want to return yet
	}
	if sb != nil {
		return Case{
			SBOMS:    []sbom.SBOM{*sb},
			Licenses: make([]License, 0),
		}, nil
	}
	licenses, err := ch.handleLicenseFile(path)
	if err != nil {
		return c, fmt.Errorf("unable to determine SBOM or licenses for %s: %w", path, err)
	}

	return Case{
		SBOMS:     make([]sbom.SBOM, 0),
		Licenses:  licenses,
		UserInput: path,
	}, nil
}

func (ch *CaseHandler) handleLicenseFile(path string) ([]License, error) {
	// alright we couldn't get an SBOM, let's see if the bytes are just a LICENSE (google license classifier)

	// google license classifier is noisy, so we'll silence it for now
	golog.SetOutput(io.Discard)
	if errs := ch.Backend.ClassifyLicensesWithContext(
		context.Background(),
		1000,
		[]string{path},
		false,
	); errs != nil {
		ch.Close()
		for _, err := range errs {
			log.Errorf("unable to classify license: %+v", err)
		}
		return nil, fmt.Errorf("unable to classify license: %+v", errs)
	}
	// re-enable logging for the rest of the application
	golog.SetOutput(os.Stdout)

	classifierResults := ch.Backend.GetResults()
	if len(classifierResults) == 0 {
		return nil, fmt.Errorf("no classifierResults from license classifier")
	}

	licenses := grantLicenseFromClassifierResults(classifierResults)
	return licenses, nil
}

func (ch *CaseHandler) handleDir(root string) (c Case, err error) {
	dirCase := Case{
		SBOMS:    make([]sbom.SBOM, 0),
		Licenses: make([]License, 0),
	}

	// the closure that will be used to visit each file node
	visit := func(s string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			// This isn't broken, the license classifier just returned two licenses
			r, err := ch.handleFile(s)
			if err != nil {
				// TODO: some log for the error here?
				return nil
			}
			dirCase.SBOMS = append(dirCase.SBOMS, r.SBOMS...)
			dirCase.Licenses = append(dirCase.Licenses, r.Licenses...)
		}
		return nil
	}

	err = filepath.WalkDir(root, visit)
	if err != nil {
		return c, err
	}
	return dirCase, nil
}

func handleContainer(image string) (c Case, err error) {
	sb, err := generateSyftSBOM(image)
	if err != nil {
		// We bail here since we can't generate an SBOM for the image
		return c, err
	}

	return Case{
		SBOMS:    []sbom.SBOM{sb},
		Licenses: make([]License, 0),
	}, nil
}

func getReadSeeker(path string) (io.ReadSeeker, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open file: %w", err)
	}
	return file, nil
}

func grantLicenseFromClassifierResults(r results.LicenseTypes) []License {
	licenses := make([]License, 0)
	for _, license := range r {
		// TODO: sometimes the license classifier gives us more information than just the name.
		// How do we want to handle this or include it in the grant.License?

		if license.MatchType == "License" {
			spdxLicense, err := spdxlicense.GetLicenseByID(license.Name)
			if err != nil {
				licenses = append(licenses, License{
					LicenseID: license.Name,
					Name:      license.Name,
				})
			} else {
				licenses = append(licenses, License{
					SPDXExpression:        spdxLicense.LicenseID,
					Reference:             spdxLicense.Reference,
					IsDeprecatedLicenseID: spdxLicense.IsDeprecatedLicenseID,
					DetailsURL:            spdxLicense.DetailsURL,
					ReferenceNumber:       spdxLicense.ReferenceNumber,
					LicenseID:             spdxLicense.LicenseID,
					SeeAlso:               spdxLicense.SeeAlso,
					IsOsiApproved:         spdxLicense.IsOsiApproved,
				})
			}
		}
	}
	return licenses
}

// TODO: is the default syft config good enough here?
// we definitely need at least all the non default license magic turned on
func generateSyftSBOM(path string) (sb sbom.SBOM, err error) {
	detection, err := source.Detect(path, source.DefaultDetectConfig())
	if err != nil {
		return sb, err
	}

	src, err := detection.NewSource(source.DefaultDetectionSourceConfig())
	if err != nil {
		return sb, err
	}
	sb = getSBOM(src)
	return sb, nil
}

func getSBOM(src source.Source) sbom.SBOM {
	createSBOMConfig := syft.DefaultCreateSBOMConfig()
	createSBOMConfig.WithPackagesConfig(
		pkgcataloging.DefaultConfig().
			WithJavaArchiveConfig(java.DefaultArchiveCatalogerConfig().WithUseNetwork(true)).
			WithJavascriptConfig(javascript.DefaultCatalogerConfig().WithSearchRemoteLicenses(true)).
			WithGolangConfig(golang.DefaultCatalogerConfig().
				WithSearchLocalModCacheLicenses(true).
				WithSearchRemoteLicenses(true)))
	s, err := syft.CreateSBOM(context.Background(), src, nil)
	if err != nil {
		panic(err)
	}

	return *s
}

func isDirectory(path string) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		// log.Errorf("unable to stat directory %s: %+v", path, err)
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
		// log.Errorf("unable to stat file %s: %+v", path, err)
		return false
	}
	return !fileInfo.IsDir()
}

// this is appended to the list of user requests if the user provides stdin
// and doesn't provide a "-" in the list of user requests
func isStdin(path string) bool {
	return strings.EqualFold(path, "-")
}
