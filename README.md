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

You can provide custom options to the testing binaries, like a custom path to the Falco executable. You just need to specify the `-falco-binary` option followed by the path:

```bash
build/falco.test -falco-binary <path_to_falco>
```

You could also run a single test with the `-test.run` option:

```bash
build/falco.test -test.run 'TestFalco_Legacy_WriteBinaryDir'
```

To check all other options use the `--help` flag.

## Usage in CI

To better suit the CI usage, a [Github composite action](https://docs.github.com/en/actions/creating-actions/creating-a-composite-action) has been developed. Therefore, running Falco tests in your Github workflow is as easy as adding this step:
```
- name: Run tests
  uses: falcosecurity/testing@main
  with:
    # Whether to test Falco.
    # Default: 'true'.
    test-falco: 'true'
    # Whether to test Falcoctl.
    # Default: 'false'.
    test-falcoctl: 'true'
    # Whether to test k8saudit.
    # Default: 'false'.
    test-k8saudit: 'true'
    # Whether to test drivers.
    # Default: 'false'.
    test-drivers: 'true'
    # Whether to run Falco in static mode in tests
    # If enabled, only Falco tests will be enabled,
    # all the others will be forcefully skipped.
    # Default: 'false'.
    static: 'false'
    # Whether to upload all tests in action-summary.
    # Default: 'false'.
    show-all: 'true'
```


## Keep tests updated with the latest Falco version

Some of these tests might become incompatible with a new Falco version, for example after a fix an old scap-file could trigger more rules than the ones expected or maybe the rule is no more triggered for a valid reason.

Falco CI runs these tests so we need to fix them before merging the new Falco version upstream. This is the usual flow to follow:

1. Face a test failure in a pull request on the Falco repository (or detect the failure locally running Falco dev against this repo).
2. Understand why these tests are failing, if there are no regressions and the Falco behavior is incompatible with actual tests, we change them accordingly.
3. Open a pull request against this repo with the necessary changes.
4. Once the pull request is merged use the derived commit to bump the submodule in the Falco repository.
From the Falco source directory:

 ```bash
 cd submodules/falcosecurity-testing
 git fetch
 git merge origin/main # or git checkout <specific-commit>
 ```

5. Commit these changes in the same pull request with the new Falco version that caused test failures. Now tests should pass.
