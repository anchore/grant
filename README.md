<p align="center">
 <img src=".github/images/grant-logo.png" width="271" alt="Grant logo" />
</p>

# Grant

**A CLI tool and Go library for checking licenses in container images, SBOMs, and filesystems. Works seamlessly with [Syft](https://github.com/anchore/syft) for license investigation and policy enforcement.**

<p align="center">
  <a href="https://github.com/anchore/grant/actions/workflows/validations.yaml"><img alt="Validations" src="https://github.com/anchore/grant/actions/workflows/validations.yaml/badge.svg" /></a>
  <a href="https://goreportcard.com/report/github.com/anchore/grant"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/anchore/grant" /></a>
  <a href="https://github.com/anchore/grant/releases/latest"><img alt="GitHub release" src="https://img.shields.io/github/release/anchore/grant.svg" /></a>
  <a href="https://github.com/anchore/grant/blob/main/go.mod"><img alt="GitHub go.mod Go version" src="https://img.shields.io/github/go-mod/go-version/anchore/grant.svg" /></a>
  <a href="https://github.com/anchore/grant/blob/main/LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" /></a>
  <a href="https://anchore.com/discourse" target="_blank"><img alt="Join our Discourse" src="https://img.shields.io/badge/Discourse-Join-blue?logo=discourse"/></a>
</p>

![grant-demo](.github/images/demo.gif)

## Features

- Check licenses in **container images**, **SBOMs**, and **filesystems**
- Categorize licenses by risk level (permissive, weak copyleft, strong copyleft)
- Define and enforce [license policies](https://oss.anchore.com/docs/guides/license/policies/) with allow/deny lists
- Works seamlessly with [Syft](https://github.com/anchore/syft) SBOMs
- Multiple output formats (**table**, **JSON**) for CI/CD integration

> [!TIP]
> **New to Grant? Check out the [Getting Started guide](https://oss.anchore.com/docs/guides/license/getting-started) for a walkthrough!**

## Installation

The quickest way to get up and going:
```bash
curl -sSfL https://get.anchore.io/grant | sudo sh -s -- -b /usr/local/bin
```

> [!TIP]
> **See [Installation docs](https://oss.anchore.com/docs/installation/grant/) for more ways to get Grant!**

## The basics

List licenses within a container image or directory:

```bash
# container image
grant list redis:latest

# directory
grant list dir:.

# SBOM document
grant list sbom.spdx.json
```

Check licenses against a policy:

```bash
grant check redis:latest
```

An SBOM can hold two kinds of license for a package: a declared license is what the package states about itself, and a concluded license is what a scanner or the author of the SBOM determined, for example by matching the text of a license file. To only consider declared licenses, set this in the config file:

```yaml
ignore-concluded-licenses: true
require-license: true
```

Before you turn this on:

- A package whose only licenses are concluded is treated as having no licenses. It is denied only when `require-license` is `true`. A config file that leaves `require-license` out allows it, so a package that was denied for a concluded license can become allowed.
- When Grant scans an image or directory itself, every license it reads from a license file is concluded. That is the only license source for Go modules, and a common one for Debian packages and Java archives, so those packages can lose all of their licenses.
- In an SPDX SBOM, every `licenseConcluded` value is ignored, including one that a person set to correct the declared license.
- SPDX and Syft JSON SBOMs record which licenses are concluded. Grant reads every license in a CycloneDX SBOM as declared, so the option has no effect there.

Grant logs a warning with the number of licenses it ignored and the number of packages left with no licenses.

> [!TIP]
> **Check out the [Getting Started guide](https://oss.anchore.com/docs/guides/license/getting-started)** to explore all of the capabilities and features.
>
> **Want to define license policies?** Check out the [policy guide](https://oss.anchore.com/docs/guides/license/policies/).

## Contributing

We encourage users to help make these tools better by [submitting issues](https://github.com/anchore/grant/issues) when you find a bug or want a new feature.
Check out our [contributing overview](https://oss.anchore.com/docs/contributing/) and [developer-specific documentation](https://oss.anchore.com/docs/contributing/grant/) if you are interested in providing code contributions.

Grant development is sponsored by [Anchore](https://anchore.com/), and is released under the [Apache-2.0 License](https://github.com/anchore/grant?tab=Apache-2.0-1-ov-file).

For commercial support options, please [contact Anchore](https://get.anchore.com/contact/).
