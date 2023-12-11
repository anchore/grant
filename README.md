# Grant

Manage the license compliance for oci images and software projects

![grant-demo](TODO)

### Supply an image
```bash
$ grant check alpine:latest
```

#### Supply an SBOM document
```bash
$ grant check alpine.spdx.json
```

### Supply multiple sources including stdin and a mix of image and sbom
```bash
$ syft -o spdx-json alpine:latest | grant check node:latest
```


## Installation
```bash
curl -sSfL https://raw.githubusercontent.com/anchore/grant/main/install.sh | sh -s -- -b /usr/local/bin
```


... or, you can specify a release version and destination directory for the installation:

```
curl -sSfL https://raw.githubusercontent.com/anchore/grant/main/install.sh | sh -s -- -b <DESTINATION_DIR> <RELEASE_VERSION>
```

## Usage

Grant can be used with any container image, sbom document, or directory scan to check for license compliance.

Rules take the form of a pattern to match the license against, a mode to either allow or deny the license,
a reason for the rule, and a list of packages that are exclusions to the rule.
```
pattern: "gpl-*"
mode: "deny"
reason: "GPL licenses are not allowed"
exclusions:
  - "alpine-base-layout" # We don't link against this package so we don't care about its license
```

Matching Rules:
- Denying licenses take precedence over allowing licenses
- License id are matched on a case-insensitive basis.
- If a license is has rules for both modes it is denied

Supplied patterns follow a standard globbing syntax:
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

By default grant is configured to deny all licenses out of the box.


Grant can be used to deny specific licenses, allowing all others.
It can also be used to allow specific licenses, denying all others.

## Output
#### Table
```bash
$ grant check ubuntu:latest, alpine:latest
▶ ubuntu:latest
- GPL-2.0-only
- GPL-3.0-only
- BSD-2-Clause
- BSD-3-Clause
- BSD-4-Clause
- GPL-2.0-or-later
- GPL-3.0-or-later
- LGPL-2.0-only
- LGPL-2.0-or-later
- LGPL-2.1-only
- LGPL-2.1-or-later
- LGPL-3.0-only
- LGPL-3.0-or-later
- MIT
- FSFUL
- FSFULLR
- GFDL-1.3-only
- GFDL-1.2-only
- CC0-1.0
- GPL-1.0-only
- Apache-2.0
- X11
- ISC
- GPL-1.0-or-later
- GFDL-1.2-or-later
- Zlib
- Artistic-2.0
▶ alpine:latest
- GPL-2.0-only
- MIT
- MPL-2.0
- BSD-2-Clause
- BSD-3-Clause
- Apache-2.0
- GPL-2.0-or-later
- Zlib
[return code 1]
````

#### JSON: TODO
```
```

## Configuration
```yaml
#.grant.yaml
config: ".grant.yaml"
quite: false # only print status code 1 or 0 for success or failure
rules: 
    - pattern: "gpl-*"
      mode: "deny"
      reason: "GPL licenses are not allowed"
      exclusions:
        - "alpine-base-layout" # We don't link against this package so we don't care about its license
```