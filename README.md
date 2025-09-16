<p align="center">
 <img src=".github/images/grant-logo.png" width="271" alt="Grant logo - cute green spotted creature" />
</p>

<p align="center">
  <a href="https://github.com/anchore/grant/actions/workflows/validations.yaml">
    <img alt="Validations" src="https://github.com/anchore/grant/actions/workflows/validations.yaml/badge.svg" />
  </a>
  <a href="https://goreportcard.com/report/github.com/anchore/grant">
    <img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/anchore/grant" />
  </a>
  <a href="https://github.com/anchore/grant/releases/latest">
    <img alt="GitHub release" src="https://img.shields.io/github/release/anchore/grant.svg" />
  </a>
  <a href="https://github.com/anchore/grant/blob/main/go.mod">
    <img alt="GitHub go.mod Go version" src="https://img.shields.io/github/go-mod/go-version/anchore/grant.svg" />
  </a>
  <a href="https://github.com/anchore/grant/blob/main/LICENSE">
    <img alt="License: Apache-2.0" src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" />
  </a>
 &nbsp;<a href="https://anchore.com/discourse" target="_blank"><img alt="Join our Discourse" src="https://img.shields.io/badge/Discourse-Join-blue?logo=discourse"/></a>&nbsp;
</p>

# Grant

View licenses for container images, SBOM documents, filesystems, and apply rules that help you build a license
compliance report.

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
