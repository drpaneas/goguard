package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
)

func isGoVuln(cve string) (string, error) {
	// Send an HTTP GET request to the URL
	resp, err := http.Get("https://osv.dev/list?ecosystem=&q=" + cve)
	if err != nil {
		return "", errors.New("couldn't connect to osv.dev")
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.New("cannot read the response")
	}

	// Search for the GO-YEAR-ID in the response body
	re := regexp.MustCompile(`GO-[0-9]{4}-[0-9]+`)
	match := re.FindAllString(string(body), -1)

	if len(match) == 0 {
		return "", errors.New("couldn't find any Go vulnerability entry for this CVE")
	} else if len(match) > 1 {
		// Check if there are multiple entries which are all of them identical
		allSame := true
		for i := 1; i < len(match); i++ {
			if match[i] != match[i-1] {
				allSame = false
				break
			}
		}

		// If there are multiple different entries, stop because I have no clue how to handle this
		if !allSame {
			var all string
			for _, v := range match {
				all = fmt.Sprintf("%s\t", v)
			}
			return "", errors.New("multiple different Go vuln entries were found: " + all)
		}

	}

	return match[0], nil
}
