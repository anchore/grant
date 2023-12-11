# Grant

Manage the license compliance for oci images and software projects

![grant-demo](TODO)

```bash
$ grant check alpine:latest
[return code 1]
```

```bash
$ grant check alpine.spdx.json
[return code 0]
```

```bash
$ syft -o spdx-json alpine:latest | grant check
[return code 0]
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

Grant can be used with any OCI image or sbom document to check for license compliance.

Matching Rules:
- Deny licenses take precedence over allow licenses
- Licenses are matched on a case-insensitive basis.
- If a license is in both lists it is denied. 
- If a license is in neither list it is denied.

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

```bash

By default grant is configured to deny all licenses out of the box.


Grant can be used to deny specific licenses, allowing all others.
It can also be used to allow specific licenses, denying all others.

The following is an example of a `deny` oriented configuration which will deny `*` and allow `MIT` and `Apache-2`:

```yaml
#.grant.yaml
deny: *
allow:
  - MIT
  - Apache-*
```

If licenses are found that are not in the allow list, grant will return status code 1.

Valid IDs that are considered are by default sourced from the most recent 
[SPDX license list](https://spdx.org/licenses/).

## TODO
In the future it will be possible for users to configure which license list
they would like to use for their `grant check` run.

## Output
```json
{
  "result": "fail",
  "reasons": [
    {
      "reason": "'GPL-1' is not allowed with rule 'GPL*'",
      "package": {
        "name": "my-pkg",
        "version": "v1.0.0",
        "location": "/etc/my-pkg"
      }
    }

  ]

}
[return code 1]
```

## Configuration
```yaml
#.grant.yaml
config: ".grant.yaml"
log-level: "info"
rules: 
    - pattern: "gpl-*"
      name: "deny all gpl"
      reason: "GPL licenses are not allowed"
      severity: "high"
      exclusions:
        - "alpine-base-layout" # We don't link against this package so we don't care about its license
```