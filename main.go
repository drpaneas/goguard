package main

import (
	"fmt"
	"os"
)

var debug bool

func main() {
	// User Input Validation
	cve, repoURL, err := getUserInput()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Check if the CVE ID is in the database
	if !isInVDB(cve) {
		fmt.Println("CVE ID not found in NVD database")
		os.Exit(1)
	}

	// Check all the args if there is --debug flag
	for _, arg := range os.Args {
		if arg == "--debug" {
			debug = true
		}
	}

	// Check if the CVE is related to Go vulnerabilities
	goID, err := isGoVuln(cve)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if debug {
		fmt.Println("GoID:", goID)
	}

	// Get the Go package and version from from GoID
	pkg, fixedVersion, err := getGoPackage(goID)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if debug {
		fmt.Println("Package:", pkg)
		fmt.Println("Fixed Version:", fixedVersion)
	}

	// Check if the repo to see if the pkg with the vulnerable version is used
	if err := isVulnerable(repoURL, pkg, fixedVersion); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

}
