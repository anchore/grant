# Grant

View licenses for container images, SBOM documents, filesystems, and apply rules that help you build a license
compliance report.

![demo](https://github.com/anchore/grant/assets/32073428/981be7c0-582f-4966-a1e9-31e770aba9eb)

### Supply an image
```bash
$ grant check redis:latest
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

Grant can be used with any container image, sbom document, or directory to scan for licenses and check those classifierResults
against a set of rules provided by the user.

Rules take the form of a pattern to match the license against, a name to identify the rule, a mode to either allow,
deny, or ignore the license,
a reason for the rule, and a list of packages that are exclusions to the rule.
```
pattern: "*gpl*"
name: "deny-gpl"
mode: "deny"
reason: "GPL licenses are not allowed"
exclusions:
  - "alpine-base-layout" # We don't link against this package so we don't care about its license
```

Matching Rules:
- Denying licenses take precedence over allowing licenses
- License patterns are matched on a case-insensitive basis.
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

Grant can be used to deny specific licenses while allowing all others.

It can also be used to allow specific licenses, denying all others.

## Output
#### Table
![table-output](https://github.com/anchore/grant/assets/32073428/59a516de-3acd-4f4a-8861-4e90eae09866)

#### JSON: TODO
![json-output](https://github.com/anchore/grant/assets/32073428/c2d89645-e323-4f99-a179-77e5a750ee6a)

## Configuration

### Example: Deny GPL

```yaml
#.grant.yaml
config: ".grant.yaml"
format: table # table, json
show-packages: false # show the packages which contain the licenses --show-packages
non-spdx: false # list only licenses that could not be matched to an SPDX identifier --non-spdx
osi-approved: false # highlight licenses that are not OSI approved --osi-approved
rules: 
    - pattern: "*gpl*"
      name: "deny-gpl"
      mode: "deny"
      reason: "GPL licenses are not allowed per xxx-xx company policy"
      exclusions:
        - "alpine-base-layout" # We don't link against this package so we don't care about its license
```

### Example: Allow Lists

In this example, all licenses are denied except BSD and MIT:

```yaml
#.grant.yaml
rules:
  - pattern: "BSD-*"
    name: "bsd-allow"
    mode: "allow"
    reason: "BSD is compatible with our project"
    exceptions:
      # Packages to disallow even if they are licensed under BSD.
      - my-package
  - pattern: "MIT"
    name: "mit-allow"
    mode: "allow"
    reason: "MIT is compatible with our project"
  # Reject the rest.
  - pattern: "*"
    name: "default-deny-all"
    mode: "deny"
    reason: "All licenses need to be explicitly allowed"
```
