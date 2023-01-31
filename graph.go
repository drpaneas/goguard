package main

import (
	"bytes"
	"errors"
	"fmt"
	"golang.org/x/mod/semver"
	"io"
	"net/http"
	"os/exec"
	"strings"
)

func runModGraph(repoURL string) (string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	// Get the name of the repo (aka the folder, to do 'cd repoName')
	segments := strings.Split(repoURL, "/")
	lastPart := segments[len(segments)-1]
	repoName := lastPart

	cmd := exec.Command("docker", "run", "--rm", "golang", "sh", "-c",
		fmt.Sprintf("git clone %s.git; cd %s; go mod graph;", repoURL, repoName))
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("%s: %s", err, stderr.String())
	}

	return stdout.String(), nil
}

func checkIndirectVulnerability(output, pkg, fixed string) (bool, []string, []string) {
	lines := strings.Split(output, "\n")

	var safeList []string
	var vulnerableList []string

	isVulnerable := false
	for _, line := range lines {
		if !strings.Contains(line, pkg) {
			continue
		}

		parts := strings.Split(line, " ")
		if len(parts) != 2 {
			continue
		}

		dep := parts[1]
		depParts := strings.Split(dep, "@")
		if len(depParts) != 2 {
			continue
		}

		verStr := depParts[1]
		if !semver.IsValid(verStr) {
			continue
		}

		if !semver.IsValid(fixed) {
			continue
		}

		switch semver.Compare(verStr, fixed) {
		case -1:
			isVulnerable = true
			message := fmt.Sprintf("Indirect Dependency: [VULNERABLE] package '%s' imports '%s' with version '%s' (is less than %s)", parts[0], pkg, verStr, fixed)
			vulnerableList = append(vulnerableList, message)
		case 0:
			message := fmt.Sprintf("Indirect Dependency: [SAFE] package '%s' imports '%s' with version '%s' (equals to %s)", parts[0], pkg, verStr, fixed)
			safeList = append(safeList, message)

		case 1:
			message := fmt.Sprintf("Indirect Dependency: [SAFE] package '%s' imports '%s' with version '%s' (newer to %s)", parts[0], pkg, verStr, fixed)
			safeList = append(safeList, message)
		}
	}

	return isVulnerable, safeList, vulnerableList
}

func checkSum(repoURL, vulnPackage, fixedVersion string) (bool, []string, error) {
	var isAffected bool // Assume the package is not vulnerable
	var packageName, version string
	var vulnPkgs []string

	// Replace with the link to the go.sum file on GitHub
	// url := repoURL + "/raw/master/go.sum"
	url := strings.TrimSuffix(repoURL, "/") + "/raw/master/go.sum"

	response, err := http.Get(url)
	if err != nil {
		errMessage := fmt.Sprintf("Error while getting go.sum file: %s", err)
		return isAffected, vulnPkgs, errors.New(errMessage)
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
		return isAffected, vulnPkgs, errors.New(errMessage)
	}

	contents, err := io.ReadAll(response.Body)
	if err != nil {
		errMessage := fmt.Sprintf("Error while reading go.sum file: %s", err)
		return isAffected, vulnPkgs, errors.New(errMessage)
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
			vulnPkgs = append(vulnPkgs, version)
		}

	}

	if !isAffected {
		return isAffected, vulnPkgs, nil
	}

	return isAffected, vulnPkgs, nil

}
