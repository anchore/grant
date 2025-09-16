<p align="center">
 <img src=".github/images/grant-logo.png" width="271" alt="Grant logo - cute green spotted creature" />
</p>

<p align="center">
  <a href="https://github.com/anchore/grant/actions/workflows/validations.yaml"><img alt="Validations" src="https://github.com/anchore/grant/actions/workflows/validations.yaml/badge.svg" /></a>
  <a href="https://goreportcard.com/report/github.com/anchore/grant"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/anchore/grant" /></a>
  <a href="https://github.com/anchore/grant/releases/latest"><img alt="GitHub release" src="https://img.shields.io/github/release/anchore/grant.svg" /></a>
  <a href="https://github.com/anchore/grant/blob/main/go.mod">    <img alt="GitHub go.mod Go version" src="https://img.shields.io/github/go-mod/go-version/anchore/grant.svg" /></a>
  <a href="https://github.com/anchore/grant/blob/main/LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" /></a>
 &nbsp;<a href="https://anchore.com/discourse" target="_blank"><img alt="Join our Discourse" src="https://img.shields.io/badge/Discourse-Join-blue?logo=discourse"/></a>&nbsp;
</p>

# Grant

View licenses for container images, SBOM documents, and filesystems! Apply filters and views that can help you build a picture of licenses in your SBOM. Grant provides powerful filtering and cli capabilities for tackling license investigation and management, including license risk categorization.

<p align="center">
 <img src=".github/images/demo.gif" width="800" alt="Grant demo - program does license work in terminal" />
</p>

## Quick Start

## Installation
```bash
curl -sSfL https://get.anchore.io/grant | sudo sh -s -- -b /usr/local/bin
```
... or, you can specify a release version and destination directory for the installation:

```
curl -sSfL https://get.anchore.io/grant | sudo sh -s -- -b <DESTINATION_DIR> <RELEASE_VERSION>
```

### Supply an image to view the licenses found in the image
```bash
$ grant list redis:latest
```

### Supply an SBOM document and see all the licenses in that document
```bash
$ grant list alpine.spdx.json
```

### Supply an SBOM document by piping syft | grant to preserve your syft config
```bash
$ syft -o json alpine:latest | grant list -
```

### Supply an SBOM document via cat. Filters work on stdin
```bash
$ cat cyclonedx.json | grant list - "GPL-3.0-only"
```


### Check a local directory for licenses
```bash
$ grant list dir:.
```

### Group licenses by risk category
```bash
$ grant list node:latest --group-by risk
 ✔ Loaded alpine:latest
 ✔ License listing
 ✔ Aggregated by risk

 RISK CATEGORY    LICENSES  PACKAGES
 Strong Copyleft         2         9
 Weak Copyleft           1         1
 Permissive              4         8
```

### Filter packages by license and get detailed information
```bash
# Show only packages with MIT license
$ grant list dir:. "MIT"

# Show only packages with MIT or Apache-2.0
$ grant list redis:latest 'Apache-2.0' 'MIT'

# Get detailed info about a specific package
$ grant list dir:. "MIT" --pkg "github.com/BurntSushi/toml"
 ✔ Loaded dir:.
 ✔ License listing
 ✔ Package details                    [package="github.com/BurntSushi/toml"]
 ✔ Found package instances           [1 instance]

Name:     github.com/BurntSushi/toml
Version:  v1.5.0
Type:     go-module
ID:       go-module:github.com/BurntSushi/toml@v1.5.0
Licenses (1):

• MIT
  OSI Approved: true | Deprecated: false

# Save results to JSON file for continued processing (no rescan)
$ grant list dir:. -f licenses.json
$ cat licenses.json | grant list - "Apache-2.0"
```

## Usage

Grant can be used with any container image, sbom document, or directory to scan for licenses and evaluate them against a license configuration.

**Default Behavior:**
- **DENY all licenses** except those explicitly permitted in the `allow` list
- **DENY packages without licenses** (when `require-license` is true)
- **Allow packages with non-SPDX/unparsable licenses** (when `require-known-license` is false)

**Configuration Options:**
- `allow`: List of license patterns to permit (supports glob patterns)
- `ignore-packages`: List of package patterns to exclude from license checking
- `require-license`: Set to `false` to allow packages with no detected licenses (default: `false`)
- `require-known-license`: Set to `false` to allow non-SPDX/unparsable licenses (default: `false`)

License patterns support standard globbing syntax:
```
pattern:
{ term }

term:
`*`         matches any sequence of non-separator characters
`**`        matches any sequence of characters
`?`         matches any single non-separator character
`[` [ `!` ] { character-range } `]`
character class (must be non-empty)
`{` pattern-list `}`
pattern alternatives
c           matches character c (c != `*`, `**`, `?`, `\`, `[`, `{`, `}`)
`\` c       matches character c

character-range:
c           matches character c (c != `\\`, `-`, `]`)
`\` c       matches character c
lo `-` hi   matches character c for lo <= c <= hi

pattern-list:
pattern { `,` pattern }
comma-separated (without spaces) patterns
```

## Configuration

### Basic Configuration
```yaml
#.grant.yaml
# Default behavior: DENY all licenses except those explicitly permitted
# Default behavior: DENY packages without licenses
require-license: false        # Deny packages with no detected licenses
require-known-license: false # Deny non-SPDX / unparsable licenses

# Allowed licenses (glob patterns supported)
allow:
  - BSD*
  - CC0*
  - MIT*
  - Apache*
  - MPL*
  - ISC
  - WTFPL
  - Unlicense

ignore-packages:
  # packageurl-go is released under the MIT license located in the root of the repo at /mit.LICENSE
  - github.com/anchore/packageurl-go

  # syft is under the Apache-2 license but gets flagged because of some test dependencies
  - github.com/anchore/syft
```

### License Detection Modes

By default, Grant performs two types of license detection:

1. **SBOM-based detection**: Analyzes package manifests and metadata to identify licenses associated with specific packages
2. **File-based detection**: Searches the filesystem for standalone license files (LICENSE, COPYING, etc.) that may not be associated with any specific package

The `--disable-file-search` option allows you to skip the second type of detection while still performing SBOM generation and package-based license detection. This can be useful when:
- You only want licenses that are directly associated with packages
- You need faster scanning by avoiding filesystem traversal for license files

**Note**: SBOM generation includes its own file analysis process which will still run regardless of the `--disable-file-search` setting.

## License Risk Categories

Grant categorizes licenses based on their legal risk and restrictions:

### Risk Levels

- **High Risk (Strong Copyleft)**: Licenses requiring derivative works to be licensed under the same terms
  - Examples: GPL, AGPL, SSPL
  - Color: Red in terminal output

- **Medium Risk (Weak Copyleft)**: Licenses with limited copyleft requirements
  - Examples: LGPL, MPL, EPL
  - Color: Yellow in terminal output

- **Low Risk (Permissive)**: Licenses allowing proprietary use with minimal restrictions
  - Examples: MIT, Apache-2.0, BSD
  - Color: Green in terminal output

### Risk Information Display

The risk category appears as an additional column in all table views:

1. **Standard List View**: Shows risk level for each package
```bash
$ grant list dir:. "MIT"
NAME                     VERSION    LICENSE    RISK
github.com/pkg/errors    v0.9.1     MIT        Low
```

2. **Aggregated License View**: Shows risk for each unique license
```bash
$ grant list dir:.
LICENSE        PACKAGES    RISK
MIT                 114    Low
Apache-2.0          117    Low
GPL-3.0-only          3    High
```

3. **Group by Risk View**: Aggregates all licenses by risk category
```bash
$ grant list dir:. --group-by risk
RISK CATEGORY    LICENSES    PACKAGES
Strong Copyleft         7           3
Weak Copyleft           8          11
Permissive             10         299
```

### Enhanced Output Features

- **Clickable License Names**: License names in terminal output are hyperlinked to SPDX documentation
- **Risk Aggregation**: When packages have multiple licenses with different risks, shows highest risk with count of others
- **Color-Coded Risk**: Risk levels are color-coded for quick visual scanning (Red/Yellow/Green)
- **JSON Output Enhancement**: Risk categories are included in JSON output for programmatic processing

## Advanced Features

### JSON Output to File

Grant can write JSON output to a file while still displaying table output in the terminal. This is useful for automation and further processing:

```bash
# Save JSON output to file while showing table in terminal
grant list dir:. --output-file output.json
grant check dir:. --output-file results.json

# -f is the shorthand flag
grant list dir:. -f output.json

# Output JSON to both terminal and file
grant list dir:. -o json -f output.json

# Write to file with quiet mode (minimal terminal output)
grant list dir:. -f output.json -q
grant check dir:. -o json -f results.json -q
```

The JSON output contains complete machine-readable data regardless of the terminal display format.
**Output Control Options:**
- By default, grant shows table output in terminal and writes JSON to file
- Use `-o json` to show JSON in terminal AND write to file
- Use `-q` (quiet mode) for minimal terminal output when writing to file (useful for scripts and CI/CD)

### JSON Input Processing

Grant can use its own JSON output as input so you don't have to regenerate a scan if nothing changed. SBOMS also work.

```bash
# Save results and reprocess them
grant list dir:. -f results.json
cat results.json | grant list -

# Apply different filters to saved results
cat results.json | grant list - "MIT"
cat results.json | grant check -

# Chain operations
grant list dir:. -f all-packages.json
cat all-packages.json | grant list - "GPL-3.0-only" --pkg "some/package"
```

This enables:
- **Result caching**: Save expensive analysis results for reuse
- **Offline analysis**: Process results without re-scanning targets
- **Workflow automation**: Chain grant commands in scripts
- **Filter experimentation**: Try different license filters on the same dataset

### Output Modes and Flags

Grant supports multiple output modes and combinations:

```bash
# Unlicensed packages
grant check --unlicensed dir:.         # Shows packages without licenses
grant list --unlicensed dir:.         # Shows packages without licenses during list

# JSON format for users to build their own views
grant list -o json dir:.               # JSON to stdout
grant check -o json dir:.              # JSON to stdout

# File output combinations
grant list dir:. -f output.json        # Table to terminal, JSON to file
grant list dir:. -o json -f out.json   # JSON to both terminal and file
grant list dir:. -f out.json -q        # JSON to file with minimal terminal output
```

### Flags and Options

| Flag | Short | Description |
|------|-------|-------------|
| `--output-file` | `-f` | Write JSON output to file |
| `--output` | `-o` | Output format (table, json) |
| `--quiet` | `-q` | Minimal output |
| `--config` | `-c` | Configuration file path |
| `--pkg` | | Show detailed package info (requires license filter) |
| `--group-by` | | Group results by specified field (risk) |
| `--summary` | | Show summary only (check command) |
| `--unlicensed` | | Show unlicensed packages only (check command) |
| `--disable-file-search` | | Skip grant independent filesystem license file detection |
| `--dry-run` | | Allow json output from check without a status code 1 |
