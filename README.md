<p align="center">
    <a href="https://github.com/OffSecToolbox/">
        <img src="https://cdn.wolfsoftware.com/assets/images/github/organisations/offsectoolbox/black-and-white-circle-256.png" alt="OffSecToolbox logo" />
    </a>
    <br />
    <a href="https://github.com/OffSecToolbox/http-inspector/actions/workflows/cicd-pipeline-shared.yml">
        <img src="https://img.shields.io/github/workflow/status/OffSecToolbox/http-inspector/CICD%20Pipeline%20(Shared)/master?label=shared%20pipeline&style=for-the-badge" alt="Github Build Status" />
    </a>
    <a href="https://github.com/OffSecToolbox/http-inspector/actions/workflows/cicd-pipeline-custom.yml">
        <img src="https://img.shields.io/github/workflow/status/OffSecToolbox/http-inspector/CICD%20Pipeline%20(Custom)/master?label=custom%20pipeline&style=for-the-badge" alt="Github Build Status" />
    </a>
    <a href="https://codecov.io/gh/OffSecToolbox/http-inspector">
        <img src="https://img.shields.io/codecov/c/gh/OffSecToolbox/http-inspector?label=code%20coverage&style=for-the-badge" alt="code coverage" />
    </a>
    <br />
    <a href="https://github.com/OffSecToolbox/http-inspector/blob/master/.github/CODE_OF_CONDUCT.md">
        <img src="https://img.shields.io/badge/Code%20of%20Conduct-blue?style=for-the-badge" />
    </a>
    <a href="https://github.com/OffSecToolbox/http-inspector/blob/master/.github/CONTRIBUTING.md">
        <img src="https://img.shields.io/badge/Contributing-blue?style=for-the-badge" />
    </a>
    <a href="https://github.com/OffSecToolbox/http-inspector/blob/master/.github/SECURITY.md">
        <img src="https://img.shields.io/badge/Report%20Security%20Concern-blue?style=for-the-badge" />
    </a>
    <a href="https://github.com/OffSecToolbox/http-inspector/issues">
        <img src="https://img.shields.io/badge/Get%20Support-blue?style=for-the-badge" />
    </a>
</p>

## Overview

```shell
usage: http-inspector.py [-h] [-d] [-v] [-4] [-6] [-A] [-s] [-u URL] [-m MAX_REDIRECTS] [-n] [-t TIMEOUT]

Check for open port(s) on target host(s)

optional flags:
  Description

  -h, --help            show this help message and exit
  -d, --debug           Very noisy (default: False)
  -v, --verbose         Verbose output - show scan results as they come in (default: False)
  -4, --ipv4-only       Scan IPv4 addresses only (default: False)
  -6, --ipv6-only       Scan IPv6 addresses only (default: False)
  -A, --all-results     Show or save all results (default is to list open ports only) (default: False)
  -s, --shuffle         Randomise the port scanning order (default: False)

required arguments:
  stuff

  -u URL, --url URL     The url you want to check (default: None)

optional arguments:
  stuff

  -m MAX_REDIRECTS, --max-redirects MAX_REDIRECTS
                        Max redirects, set 0 to disable (default: 2)
  -n, --no-check-certificate
                        Do not verify TLS chain (default: False)
  -t TIMEOUT, --timeout TIMEOUT
                        Timeout to use when making web requests (default: 5)

For detailed documentation please refer to: https://github.com/OffSecToolbox/http-inspector
```

<br />
<p align="right"><a href="https://wolfsoftware.com/"><img src="https://img.shields.io/badge/Created%20by%20Wolf%20Software-blue?style=for-the-badge" /></a></p>
