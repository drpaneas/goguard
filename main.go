package main

import (
	"os"
)

var debug bool

func main() {
	mode, err := getMode()
	if err != nil {
		errorMode()
		os.Exit(1)
	}

	if mode == CVEMode {
		cveMode()
	}

	if mode == GoMode {
		goMode()
	}

	if mode == PKGMode {
		pkgMode()
	}

}
