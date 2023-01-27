package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/mod/semver"
	"io"
	"net/http"
	"os"
)

type CVE struct {
	ID       string     `json:"id"`
	Affected []Affected `json:"affected"`
}

type Affected struct {
	Package Package `json:"package"`
	Ranges  []Range `json:"ranges"`
}

type Package struct {
	Name string `json:"name"`
}

type Range struct {
	Events []Event `json:"events"`
}

type Event struct {
	Fixed string `json:"fixed"`
}

func getGoPackage(goID string) (string, string, error) {
	var pkg, version string
	resp, err := http.Get(fmt.Sprintf("https://api.osv.dev/v1/vulns/%s", goID))
	if err != nil {
		return pkg, version, err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return pkg, version, fmt.Errorf("failed to fetch data from server, status code: %d", resp.StatusCode)
	}

	var cve CVE
	if err := json.NewDecoder(resp.Body).Decode(&cve); err != nil {
		return pkg, version, err
	}
	if len(cve.Affected) == 0 {
		return pkg, version, fmt.Errorf("no affected packages found in the data")
	}

	for _, affected := range cve.Affected {
		if len(affected.Ranges) == 0 {
			// fmt.Errorf("no range found for package: %s", affected.Package.Name)
			continue
		}
		for _, r := range affected.Ranges {
			for _, event := range r.Events {
				if event.Fixed == "" {
					continue
				}
				pkg = affected.Package.Name
				version = event.Fixed
			}
		}
	}

	// Check if the version is valid Go semver version
	if err != isValidGoSemver(version) {
		// Usually this happens because the version missing the "v" prefix
		// so instead of v1.1.1 is 1.1.1
		// Try to fix it by adding the "v" prefix and check again
		version = "v" + version
		if err != isValidGoSemver(version) {
			return pkg, version, err
		}
	}

	return pkg, version, nil
}

func isValidGoSemver(version string) error {
	// Check if the version (from user) is valid using the semver package
	if !semver.IsValid(version) {
		err := fmt.Sprintf("Invalid version: %s (must be in semver format)\n", version)
		return errors.New(err)
	}

	return nil
}
