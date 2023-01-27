package main

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// getUserInput gets the user input from the command line and validates it
// is returns the CVE ID and the GitHub URL of the Go project as strings and an error if there is one
// it also prints the usage message if the user didn't provide the required arguments
// it also prints an error message if the user provided an invalid CVE ID or GitHub URL that is not a GitHub URL
func getUserInput() (string, string, error) {
	var repoURL, cve string
	var err error

	// Check if the user has provided the required arguments
	if len(os.Args) < 3 {
		err = errors.New(fmt.Sprint("Usage: ./", name, " <GitHub-Repo-URL> <CVE ID>"))
		return repoURL, cve, err
	}

	// Get the user input and validate it
	repoURL, err = validateURL(os.Args[1])
	if err != nil {
		return repoURL, cve, err
	}

	cve, err = validateCVE(os.Args[2])
	if err != nil {
		return repoURL, cve, err
	}

	return cve, repoURL, nil
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
