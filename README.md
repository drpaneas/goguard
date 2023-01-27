# GoGuard - Protect Go repos from CVE threats

<img src="./img/GoGuard.png?sanitize=true" alt="GBGraphics" width="240">

GoGuard is a tool that helps you protect your Go projects from known CVE threats. It allows you to check if a given GitHub repository is vulnerable against a specific CVE.

## How it works

* You provide GoGuard with a valid CVE (e.g. CVE-2021-4238) and a GitHub repository of a Go project (e.g. <https://github.com/user/repo>).
* GoGuard checks [NVD] (*National Vulnerability Database*) to see if the provided CVE exists.
* If the CVE exists, GoGuard visits the [OSVDB] (*Open Source Vulnerability Database*) to find a mapping between the provided CVE and a Go vulnerability.
* Using the information from the [OSVDB], GoGuard fetches the package name and the fixed version related to the Go vulnerability via the [Go Vulnerability Database].
* Finally, GoGuard visits the GitHub repository and looks at the `go.sum` file. It searches for the package related to the Go vulnerability and compares the version found in the go.sum file with the fixed version reported by the [OSVDB].
* If the package version in the `go.sum` file is older than the fixed version reported by the `OSVDB`, GoGuard informs the user that the GitHub repository is indeed vulnerable against the provided CVE.

## Installation

To install GoGuard, you need to have Go installed on your machine. Once you have Go, you can install GoGuard by running the following command:

```bash
go install github.com/user/GoGuard
```

## Usage

To use GoGuard, you can run the following command:

```bash
Usage: ./goguard <GitHub-Repo-URL> <CVE ID>
```

For example:

```bash
goguard https://github.com/user/repo CVE-2021-4238
```

This command will check if the GitHub repository `https://github.com/user/repo` is vulnerable against the CVE `CVE-2021-4238`.

You can also use the --debug parameter to see more detailed information about the vulnerability check process.

## Note

* GoGuard is currently in **beta** version!
* GoGuard only check the vulnerabilities mentioned in the `go.sum` file.

## Disclaimer

GoGuard is provided "as is" without warranty of any kind.
Use it at your own risk and always verify the information provided with the original sources.

[NVD]: https://nvd.nist.gov/
[OSVDB]: https://osv.dev/
[Go Vulnerability Database]: https://pkg.go.dev/vuln/