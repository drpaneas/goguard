# GoGuard - Protect Go repos from CVE threats

<img src="./img/GoGuard.png?sanitize=true" alt="GBGraphics" width="240">

GoGuard is a tool that helps you protect your Go projects from known CVE threats. It allows you to check if a given GitHub repository is vulnerable against a specific CVE.

## How it works

* You provide GoGuard with a valid CVE (e.g. CVE-2021-4238) and a GitHub repository of a Go project (e.g. `<https://github.com/user/repo>`).
* GoGuard checks [NVD] (*National Vulnerability Database*) to see if the provided CVE exists.
* If the CVE exists, GoGuard visits the [OSVDB] (*Open Source Vulnerability Database*) to find a mapping between the provided CVE and a Go vulnerability.
* Using the information from the [OSVDB], GoGuard fetches the package name and the fixed version related to the Go vulnerability via the [Go Vulnerability Database].
* Finally, GoGuard visits the GitHub repository and looks at the `go.mod` file. It searches for the package related to the Go vulnerability and compares the version found in the `go.mod` file with the fixed version reported by the [OSVDB].
* This is considered a direct vulnerability check.
* GoGuard goes one step further and checks for indirect vulnerabilities in the `go.sum` file as well. If there are any vulnerable versions coming from other packages, then GoGuard will inform the user about these as well.
* To do that, it spins up an ephemeral Docker container and runs `go mod graph` to get the dependency graph of the project, against the vulnerable versions found in the `go sum` file.

### How to fix a vulnerability

* To fix a directly vulnerability, bump your `go.mod` file to the fixed version and run `go mod tidy`.

* To fix all indirect vulnerabilities, (e.g. if the vulnerable pkg is `gopkg.in/yaml.v2` and the patched version `v2.4.0` then do:

```bash
go mod edit -replace gopkg.in/yaml.v2=gopkg.in/yaml.v2@v2.4.0
go mod tidy
```

## Installation

1. To install GoGuard, you need to have Go installed on your machine. Once you have Go, you can install GoGuard by running the following command:

```bash
go install github.com/drpaneas/GoGuard
```

2. You also need docker installed, up and running.

## Usage

To use GoGuard, supports 3 scan modes

1. Scan using CVE ID
2. Scan using GO Vulnerability ID
3. Scan using a specific Go package and its version

you can run the following command:

```bash
Usage: ./goguard <mode> <GitHub-Repo-URL> <CVE ID>
 -- Modes: cve, go, pkg --
  Example: goguard cve <GitHub-Repo-URL> <BRANCH> <CVE ID>)
  Example: goguard go <GitHub-Repo-URL> <BRANCH> <GOVULN ID>)
  Example: goguard pkg <GitHub-Repo-URL> <BRANCH> <VULNPKG> <VULNVER>)
```

For example:

```bash
goguard cve https://github.com/user/repo main CVE-2021-4238
goguard go https://github.com/user/repo main GO-2022-0411
goguard pkg https://github.com/user/repo main 'goutils' '1.0'
```

This command will check if the GitHub repository `https://github.com/user/repo` is vulnerable against the CVE `CVE-2021-4238`.

You can also use the --debug parameter to see more detailed information about the vulnerability check process.

## Note

* GoGuard is currently in **beta** version!
* The pkg mode was added so you can check of embargoed CVEs (private) that are not yet publicly exposed.

## Disclaimer

GoGuard is provided "as is" without warranty of any kind.
Use it at your own risk and always verify the information provided with the original sources.

[NVD]: https://nvd.nist.gov/
[OSVDB]: https://osv.dev/
[Go Vulnerability Database]: https://pkg.go.dev/vuln/
