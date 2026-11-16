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

> [!TIP]
> **Check out the [Getting Started guide](https://oss.anchore.com/docs/guides/license/getting-started)** to explore all of the capabilities and features.
>
> **Want to define license policies?** Check out the [policy guide](https://oss.anchore.com/docs/guides/license/policies/).

## Contributing

We encourage users to help make these tools better by [submitting issues](https://github.com/anchore/grant/issues) when you find a bug or want a new feature.
Check out our [contributing overview](https://oss.anchore.com/docs/contributing/) and [developer-specific documentation](https://oss.anchore.com/docs/contributing/grant/) if you are interested in providing code contributions.

Grant development is sponsored by [Anchore](https://anchore.com/), and is released under the [Apache-2.0 License](https://github.com/anchore/grant?tab=Apache-2.0-1-ov-file).

For commercial support options, please [contact Anchore](https://get.anchore.com/contact/).
