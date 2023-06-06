# Falco Regression Tests

[![Falco Infra Repository](https://github.com/falcosecurity/evolution/blob/main/repos/badges/falco-infra-blue.svg)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#infra-scope) [![Incubating](https://img.shields.io/badge/status-incubating-orange?style=for-the-badge)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#incubating) [![License](https://img.shields.io/github/license/falcosecurity/testing?style=for-the-badge)](./LICENSE)

A regression test suite for Falco and other tools in its ecosystem.
This is meant to be and end-to-end suite for black-box testing, for both individual tools and their integration, trying to emulate the same usage and patterns of the average user.

## Usage

This testing suite is implemented in Go, and Go is the only dependency required in your system.

Tests are defined as code, and as such the artifact released with the testing suite is the code itself.

First, you need to run `go generate`. This will generate part of the testing code and date required by the suite.
```
go generate ./...
```

After this, the `build` directory will be created and will contain the testing binaries and the supporting test files.
```bash
build/falco.test # run this to launch tests on Falco
build/falcoctl.test # run this to launch tests on falctocl
build/k8saudit.test # run this to launch tests on the k8saudit plugin
```

