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

View licenses for container images, SBOM documents, and filesystems! Apply filters and views that can help you build a picture of licenses in your SBOM. Grant provides powerful filtering and cli capabilities for tackling license investigation and management.

### Supply an image to view the licenses found in the image
```bash
$ grant list redis:latest
```

#### Supply an SBOM document and see all the licenses in that document
```bash
$ grant list alpine.spdx.json
```

### Check a local directory for licenses
```bash
$ grant list dir:.
```

### Filter packages by license and get detailed information
```bash
# Show only packages with MIT license
$ grant list dir:. "MIT"

# Show only packages with MIT or SMAIL-GPL
$ grant list redis:latest 'SMAIL-GPL' 'MIT'

# Get detailed info about a specific package
$ grant list dir:. "MIT" --pkg "github.com/BurntSushi/toml"

# Save results to JSON file for continued processing (no rescan)
$ grant list dir:. -f licenses.json
$ cat results.json | grant list - "Apache-2.0"
```

## Installation
```bash
curl -sSfL https://get.anchore.io/grant | sudo sh -s -- -b /usr/local/bin
```

... or, you can specify a release version and destination directory for the installation:

```
curl -sSfL https://get.anchore.io/grant | sudo sh -s -- -b <DESTINATION_DIR> <RELEASE_VERSION>
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

## Advanced Features

### JSON Output to File

Grant can write JSON output to a file while still displaying table output in the terminal. This is useful for automation and further processing:

```bash
# Save JSON output to file while showing table in terminal
grant list dir:. -f output.json
grant check dir:. --output-file results.json

# Use shorthand flag
grant list dir:. -f output.json

# Output JSON to both terminal and file
grant list dir:. -o json -f output.json

# Suppress terminal output when writing to file
grant list dir:. -f output.json --no-output
grant check dir:. -o json -f results.json --no-output
```

The JSON output contains complete machine-readable data regardless of the terminal display format.

**Output Control Options:**
- By default, grant shows table output in terminal and writes JSON to file
- Use `-o json` to show JSON in terminal AND write to file
- Use `--no-output` to suppress terminal output when writing to file (useful for scripts and CI/CD)

### License Filtering

Filter the list output to show only packages with specific licenses:

```bash
# Show only packages with MIT license
grant list dir:. "MIT"

# Show packages with MIT OR Apache-2.0 licenses
grant list dir:. "MIT" "Apache-2.0"

# Combine with output file
grant list dir:. "ISC" -f isc-packages.json
```

When license filtering is applied, the output shows:
- Filter status in the progress display
- Package and license counts for filtered results
- Detailed package table instead of aggregated license table

### Package Detail View

Get detailed information about a specific package, including complete license details and file locations:

```bash
# Show detailed info for a specific package (requires license filter)
grant list dir:. "MIT" --pkg "github.com/BurntSushi/toml"

# Combine with JSON output
grant list dir:. "MIT" --pkg "github.com/BurntSushi/toml" -f package-details.json
```

Package details include:
- Package metadata (name, version, type, ID, decision)
- Complete license information (ID, name, OSI approval, deprecation status, details URL)
- Evidence and file locations
- Support for multiple package instances

### JSON Input Processing

Grant can use its own JSON output as input, enabling powerful workflow automation:

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
# Quiet mode - minimal output
grant list -q dir:.                    # Shows license count
grant check -q dir:.                   # Shows non-compliant count

# Summary mode (check only)
grant check --summary dir:.            # Shows compliance summary

# Filtered views (list only)
grant list --licenses-only dir:.       # Shows only license information
grant list --packages-only dir:.       # Shows only package information

# Unlicensed packages (check only)
grant check --unlicensed dir:.         # Shows packages without licenses

# JSON format
grant list -o json dir:.               # JSON to stdout
grant check -o json dir:.              # JSON to stdout

# File output combinations
grant list dir:. -f output.json        # Table to terminal, JSON to file
grant list dir:. -o json -f out.json   # JSON to both terminal and file
grant list dir:. -f out.json --no-output  # JSON to file only, no terminal output
```

### Advanced Workflow Examples

**License Compliance Pipeline:**
```bash
# 1. Generate comprehensive report
grant check dir:. -f compliance-report.json

# 2. Extract packages with problematic licenses
cat compliance-report.json | grant list - "GPL-3.0-only" "AGPL-3.0-only" -f gpl-packages.json

# 3. Get detailed info about specific problematic packages
cat gpl-packages.json | grant list - "GPL-3.0-only" --pkg "some/problematic-package"
```

**License Inventory Workflow:**
```bash
# 1. Scan and save all licenses
grant list dir:. -f full-inventory.json

# 2. Filter by license families
cat full-inventory.json | grant list - "*GPL*" -f gpl-licenses.json
cat full-inventory.json | grant list - "*Apache*" -f apache-licenses.json

# 3. Generate license-only reports
cat full-inventory.json | grant list --licenses-only - > license-summary.txt
```

**Package Investigation:**
```bash
# 1. Find packages with specific license
grant list dir:. "MIT" -f mit-packages.json

# 2. Investigate specific package details
cat mit-packages.json | grant list - "MIT" --pkg "github.com/some/package"

# 3. Save detailed package info
cat mit-packages.json | grant list - "MIT" --pkg "github.com/some/package" -f package-investigation.json
```

## Quick Reference

### Common Commands

| Command | Description |
|---------|-------------|
| `grant list dir:.` | List all licenses in current directory |
| `grant check dir:.` | Check license compliance |
| `grant list dir:. "MIT"` | Show only packages with MIT license |
| `grant list dir:. -f output.json` | Save JSON output to file |
| `grant list dir:. "MIT" --pkg "package/name"` | Show detailed package information |
| `cat output.json \| grant list -` | Process saved JSON results |
| `grant check --summary dir:.` | Show compliance summary only |
| `grant list --licenses-only dir:.` | Show license information only |

### Flags and Options

| Flag | Short | Description |
|------|-------|-------------|
| `--output-file` | `-f` | Write JSON output to file |
| `--output` | `-o` | Output format (table, json) |
| `--no-output` | | Suppress terminal output when writing to file |
| `--quiet` | `-q` | Minimal output |
| `--config` | `-c` | Configuration file path |
| `--pkg` | | Show detailed package info (requires license filter) |
| `--licenses-only` | | Show only license information |
| `--packages-only` | | Show only package information |
| `--summary` | | Show summary only (check command) |
| `--unlicensed` | | Show unlicensed packages only (check command) |
