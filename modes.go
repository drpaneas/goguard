package main

import (
	"fmt"
	"os"
)

func cveMode() {
	// User Input Validation
	cve, repoURL, err := getUserInputCVEMode()
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

	// Get the Go package and version from GoID
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

func goMode() {
	// User Input Validation
	repoURL, goID, err := getUserInputGoMode()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if debug {
		fmt.Println("GoID:", goID)
	}

	// Get the Go package and version from GoID
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

func pkgMode() {
	// User Input Validation
	repoURL, pkg, fixedVersion, err := getUserInputPKGMode()
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

func errorMode() {
	fmt.Println("Usage: ./goguard <mode> <GitHub-Repo-URL> <CVE ID>")
	fmt.Println(" -- Modes: cve, go, pkg --")
	fmt.Println("  Example: goguard cve <GitHub-Repo-URL> <CVE ID>)")
	fmt.Println("  Example: goguard go <GitHub-Repo-URL> <GOVULN ID>)")
	fmt.Println("  Example: goguard pkg <GitHub-Repo-URL> <VULNPKG> <VULNVER>)")
}
