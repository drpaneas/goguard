package main

import (
	"bufio"
	"errors"
	"fmt"
	"golang.org/x/mod/semver"
	"io"
	"net/http"
	"strings"
)

func isVulnerable(repoURL, vulnPackage, fixedVersion string) error {
	// Replace with the link to the go.mod file on GitHub
	// url := repoURL + "/raw/master/go.mod"
	url := strings.TrimSuffix(repoURL, "/") + "/raw/master/go.mod"

	response, err := http.Get(url)
	if err != nil {
		errMessage := fmt.Sprintf("Error while getting go.mod file: %s", err)
		return errors.New(errMessage)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Printf("Error while closing go.mod file: %s", err)
		}
	}(response.Body)

	// If response is not 200, return error
	if response.StatusCode != 200 {
		errMessage := fmt.Sprintf("Error while getting go.mod file: %s", response.Status)
		return errors.New(errMessage)
	}

	contents, err := io.ReadAll(response.Body)
	if err != nil {
		errMessage := fmt.Sprintf("Error while reading go.mod file: %s", err)
		return errors.New(errMessage)
	}

	// Convert contents into io.Reader
	r := strings.NewReader(string(contents))

	var pkgs, versions []string

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "require (") {
			for scanner.Scan() {
				line = scanner.Text()
				if strings.HasPrefix(line, ")") {
					break
				}
				if !strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, " ") {
					continue
				}

				f := strings.Fields(line)
				pkgs = append(pkgs, f[0])
				versions = append(versions, f[1])

				if debug {
					fmt.Printf("Require statement: %s %s\n", f[0], f[1])
				}
			}
		} else if strings.HasPrefix(line, "replace (") {
			for scanner.Scan() {
				line = scanner.Text()
				if strings.HasPrefix(line, ")") {
					break
				}
				if !strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "\t") {
					continue
				}
				// It should contain "=>" otherwise it's not a replace statement
				if !strings.Contains(line, "=>") {
					continue
				}

				// find where '=>' is and split the string there to get the package name and version number
				// there should be the next two fields
				f := strings.Split(line, "=>")

				// if there is "\t" or " " in the package name, remove it
				if strings.HasPrefix(f[0], "\t") {
					f[0] = strings.TrimPrefix(f[0], "\t")
				} else if strings.HasPrefix(f[0], " ") {
					f[0] = strings.TrimPrefix(f[0], " ")
				} else {
					// if there is no "\t" or " " in the package name, it's not a valid replace statement
					continue
				}

				// If you find something here, it's not a valid replace statement, that means there is already a package with the same name
				// loop through the packages and see if there is a package with the same name as the one in the replace statement
				// if there is, then change this one instead of appending it
				// if there isn't, then append it
				for i, pkg := range pkgs {
					if pkg == f[0] {
						pkgs[i] = f[0]
						versions[i] = f[1]
						continue
					}
				}

				// if there is no package with the same name, append it
				if debug {
					fmt.Println("Replace statement: ", f[0], "=>", f[1])
				}

				pkgs = append(pkgs, f[0])
				versions = append(versions, f[1])
			}
		}
	}

	isPkgFound := false
	// loop through all the packages and see if there is a any package that is 'vulnPackage'
	for i, pkg := range pkgs {
		if pkg == vulnPackage {
			isPkgFound = true
			// if there is, check if the version is less than the fixed version
			if semver.Compare(versions[i], fixedVersion) < 0 {
				// if it is, then it's vulnerable
				fmt.Printf("Direct dependency check: [VULNERABLE] Package %s is vulnerable with version %s (is less than %s)\n", pkg, versions[i], fixedVersion)
			} else {
				fmt.Printf("Direct dependency check: [SAFE] Package %s is NOT vulnerable with version %s (patched version: %s)\n", pkg, versions[i], fixedVersion)
			}
		}
	}
	if !isPkgFound {
		fmt.Printf("Direct dependency check: [SAFE] Vulnerable Package %s is NOT found in go.mod file\n", vulnPackage)
	}

	// Indirect dependency check

	// First check the go.sum file
	// If the vulnerable package is found in the go.sum file, then it's vulnerable and we will analyze this using the go mod graph command
	isGoSumVulnerable, vulnGoSumList, err := checkSum(repoURL, vulnPackage, fixedVersion)
	if err != nil {
		fmt.Println(err)
		return err
	}

	if !isGoSumVulnerable {
		fmt.Println("Indirect Dependency check: [SAFE] Vulnerable Package Version is NOT found in the go.sum file")
		if debug {
			for _, pkg := range vulnGoSumList {
				fmt.Println(" * " + pkg)
			}
		}
		return nil
	}

	// If we are here, it means that the vulnerable package is found in the go.sum file
	// Analyze it with graph command

	output, err := runModGraph(repoURL)
	if err != nil {
		fmt.Println(err)
		return err
	}

	isIndirectVulnerable, safeList, vulnList := checkIndirectVulnerability(output, vulnPackage, fixedVersion)
	if !isIndirectVulnerable {
		fmt.Println("If you see this, file a bug report")
		fmt.Println("Indirect Dependency check: [SAFE] Vulnerable Package Version is NOT found in the dependency graph")
		if debug {
			for _, pkg := range safeList {
				fmt.Println(" * " + pkg)
			}
		}
		return nil
	}

	// Print the list of vulnerable packages
	fmt.Println("Indirect Dependency check: [VULNERABLE] List of vulnerable packages:")
	for _, pkg := range vulnGoSumList {
		fmt.Println(" * Version:" + pkg)
		for _, pkg2 := range vulnList {
			if strings.Contains(pkg2, pkg) {
				fmt.Println("   * " + pkg2)
			}
		}
		fmt.Println("------")
	}

	return nil
}
