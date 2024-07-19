package main

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// scanMode is the current mode of the scan
type scanMode int

const (
	CVEMode scanMode = iota
	GoMode
	PKGMode
	ErrorMode
)

func getMode() (scanMode, error) {
	if len(os.Args) < 2 {
		return ErrorMode, errors.New("no mode specified")
	}

	mode := os.Args[1] // get the mode from the command line

	switch mode {
	case "cve":
		return CVEMode, nil
	case "go":
		return GoMode, nil
	case "pkg":
		return PKGMode, nil
	default:
		fmt.Println("Error: unsupported mode specified")
		return ErrorMode, errors.New("invalid mode specified")
	}
}

// getUserInput gets the user input from the command line and validates it
// is returns the CVE ID and the GitHub URL of the Go project as strings and an error if there is one
// it also prints the usage message if the user didn't provide the required arguments
// it also prints an error message if the user provided an invalid CVE ID or GitHub URL that is not a GitHub URL
func getUserInputCVEMode() (string, string, string, error) {
	// this is CVEState: ./goguard cve <GitHub-Repo-URL> <CVE ID>
	// this is GoState:  ./goguard go <GitHub-Repo-URL> <GOVULN ID>
	// this is PKGState: ./goguard pkg <GitHub-Repo-URL> <VULNPKG> <VULNVER>

	var repoURL, branch, cve string
	var err error
	// Check if the user has provided the required arguments
	if len(os.Args) < 5 {
		err = errors.New(fmt.Sprint("Usage: ", name, " cve <GitHub-Repo-URL> <CVE ID>"))
		return repoURL, branch, cve, err
	}

	// Get the user input and validate it
	repoURL, err = validateURL(os.Args[2])
	if err != nil {
		return repoURL, branch, cve, err
	}
	branch = os.Args[3]

	cve, err = validateCVE(os.Args[4])
	if err != nil {
		return repoURL, branch, cve, err
	}

	return repoURL, branch, cve, nil
}

func validateURL(url string) (string, error) {
	var err error

	if !strings.HasPrefix(url, "https://") {
		if strings.HasPrefix(url, "http://") {
			url = strings.Replace(url, "http://", "https://", 1)
		} else {
			url = "https://" + url
		}
	}

	url = strings.TrimSuffix(url, "/") // remove trailing slash if it exists

	if !strings.Contains(url, githubURL) {
		url = "" // clear the URL
		err = errors.New("invalid GitHub URL")
	}

	return url, err
}

func validateCVE(cve string) (string, error) {
	var err error

	// User Input Validation, ensure CVE ID is in the correct format
	if !strings.HasPrefix(cve, "CVE-") {
		err = errors.New("invalid CVE ID: Missing 'CVE-' prefix")
		return cve, err
	}

	// regular expression pattern for validating the syntax of a CVE
	pattern := "^CVE-\\d{4}-\\d{4,}$"
	if valid, _ := regexp.MatchString(pattern, cve); !valid {
		err = errors.New("invalid CVE ID: CVE ID must be in the format CVE-YYYY-XXXX")
		return cve, err
	}

	return cve, nil
}

func getUserInputGoMode() (string, string, string, error) {
	// this is GoState:  ./goguard go <GitHub-Repo-URL> <GOVULN ID>

	var repoURL, branch, govuln string
	var err error

	// Check if the user has provided the required arguments
	if len(os.Args) < 4 {
		err = errors.New(fmt.Sprint("Usage: ", name, " go <GitHub-Repo-URL> <GOVULN ID>"))
		return repoURL, branch, govuln, err
	}

	// Get the user input and validate it
	repoURL, err = validateURL(os.Args[2])
	if err != nil {
		return repoURL, branch, govuln, err
	}

	branch = os.Args[3]
	govuln = os.Args[4]

	re := regexp.MustCompile(`GO-[0-9]{4}-[0-9]+`)
	match := re.FindAllString(string(govuln), -1)
	if len(match) == 0 {
		return repoURL, branch, govuln, errors.New("no valid format for GOVULN ID. It must be in the format GO-YYYY-XXXX")
	}

	return repoURL, branch, govuln, nil
}

func getUserInputPKGMode() (string, string, string, string, error) {
	// this is PKGState: ./goguard pkg <GitHub-Repo-URL> <VULNPKG> <VULNVER>

	var repoURL, branch, vulnpkg, vulnver string
	var err error

	// Check if the user has provided the required arguments
	if len(os.Args) < 5 {
		err = errors.New(fmt.Sprint("Usage: ", name, " pkg <GitHub-Repo-URL> <VULNPKG> <VULNVER>"))
		return repoURL, branch, vulnpkg, vulnver, err
	}

	// Get the user input and validate it
	repoURL, err = validateURL(os.Args[2])
	if err != nil {
		return repoURL, branch, vulnpkg, vulnver, err
	}

	branch = os.Args[3]
	vulnpkg = os.Args[4]
	vulnver = os.Args[5]

	// Validate the version
	if err != isValidGoSemver(vulnver) {
		// Usually this happens because the version missing the "v" prefix
		// so instead of v1.1.1 is 1.1.1
		// Try to fix it by adding the "v" prefix and check again
		vulnver = "v" + vulnver
		if err != isValidGoSemver(vulnver) {
			return repoURL, branch, vulnpkg, vulnver, errors.New("invalid version format. It must be in the format v1.1.1")
		}
	}

	return repoURL, branch, vulnpkg, vulnver, nil
}
