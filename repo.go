package main

import (
	"errors"
	"fmt"
	"golang.org/x/mod/semver"
	"io"
	"net/http"
	"strings"
)

func isVulnerable(repoURL, vulnPackage, fixedVersion string) error {
	var isAffected bool // Assume the package is not vulnerable
	var packageName, version string

	// Replace with the link to the go.sum file on GitHub
	// url := repoURL + "/raw/master/go.sum"
	url := strings.TrimSuffix(repoURL, "/") + "/raw/master/go.sum"

	response, err := http.Get(url)
	if err != nil {
		errMessage := fmt.Sprintf("Error while getting go.sum file: %s", err)
		return errors.New(errMessage)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Printf("Error while closing go.sum file: %s", err)
		}
	}(response.Body)

	// If response is not 200, return error
	if response.StatusCode != 200 {
		errMessage := fmt.Sprintf("Error while getting go.sum file: %s", response.Status)
		return errors.New(errMessage)
	}

	contents, err := io.ReadAll(response.Body)
	if err != nil {
		errMessage := fmt.Sprintf("Error while reading go.sum file: %s", err)
		return errors.New(errMessage)
	}

	lines := strings.Split(string(contents), "\n")

	// Iterate through each line in the go.sum file and look for the vulnPackage
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Split(line, " ")
		if len(parts) != 3 {
			fmt.Printf("Skipping invalid line in go.sum file: %s\n", line)
			continue
		}

		packageName = parts[0]
		version = strings.TrimSuffix(parts[1], "/go.mod")

		// Check if the version is valid using the semver package
		if !semver.IsValid(version) {
			fmt.Printf("Skipping invalid version: %s", version)
			continue
		}

		// Check if the user's package exists in the go.sum file (it can be part of)
		if packageName != vulnPackage {
			if !strings.Contains(packageName, vulnPackage) {
				continue
			}
		}

		if debug {
			fmt.Printf("Found vulnerable package: %s\n", vulnPackage)
		}

		// Check if the user's version is vulnerable
		if semver.Compare(version, fixedVersion) < 0 { // version < fixedVersion
			isAffected = true
			break
		}
	}

	if !isAffected {
		fmt.Printf("Package %s is not vulnerable (version %s is not less than %s)\n", vulnPackage, version, fixedVersion)
		return nil
	}

	fmt.Printf("Vulnerable package %s found (version %s is less than %s). ", vulnPackage, version, fixedVersion)
	fmt.Printf("Please update to version %s or higher!\n", fixedVersion)
	return nil

}
