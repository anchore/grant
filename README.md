# Grant

Manage the license compliance for oci images and software projects

![grant-demo](TODO)

```bash
$ grant check alpine:latest
[return code 1]
```

By default it's configured to deny all licenses out of the box.

## Installation
```bash
curl -sSfL https://raw.githubusercontent.com/anchore/grant/main/install.sh | sh -s -- -b /usr/local/bin
```


... or, you can specify a release version and destination directory for the installation:

```
curl -sSfL https://raw.githubusercontent.com/anchore/grant/main/install.sh | sh -s -- -b <DESTINATION_DIR> <RELEASE_VERSION>
```

## Usage

The following is an example of a `deny` oriented configuration:

```yaml
#.grant.yaml
precedence: [deny, allow]
deny: *
allow:
  - MIT
  - Apache-2
```

If licenses are found that are not in the allow list grant will return status code 1.

The IDs that are considered are sourced from the most recent 
[SPDX license list](https://spdx.org/licenses/).

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
