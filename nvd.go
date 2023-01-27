package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func isInVDB(cveID string) bool {
	exists, err := checkIfCVExists(cveID)
	if err != nil {
		fmt.Printf("Error: %v", err)
		return false
	}
	if exists {
		return true
	}

	return false
}

// NVDResponse is a struct to hold the response from the NVD API
type NVDResponse struct {
	ResultsPerPage int `json:"resultsPerPage"`
	StartIndex     int `json:"startIndex"`
	TotalResults   int `json:"totalResults"`
	Result         struct {
		CveItems []struct {
			Cve struct {
				Problemtype struct {
					ProblemtypeData []struct {
						Description []struct {
							Lang  string `json:"lang"`
							Value string `json:"value"`
						} `json:"description"`
					} `json:"problemtype_data"`
				} `json:"problemtype"`
				References struct {
					ReferenceData []struct {
						URL       string   `json:"url"`
						Name      string   `json:"name"`
						Refsource string   `json:"refsource"`
						Tags      []string `json:"tags"`
					} `json:"reference_data"`
				} `json:"references"`
				Description struct {
					DescriptionData []struct {
						Lang  string `json:"lang"`
						Value string `json:"value"`
					} `json:"description_data"`
				} `json:"description"`
			} `json:"cve"`
			Impact struct {
				BaseMetricV3 struct {
					CvssV3 struct {
						Version               string  `json:"version"`
						VectorString          string  `json:"vectorString"`
						AttackVector          string  `json:"attackVector"`
						AttackComplexity      string  `json:"attackComplexity"`
						PrivilegesRequired    string  `json:"privilegesRequired"`
						UserInteraction       string  `json:"userInteraction"`
						Scope                 string  `json:"scope"`
						ConfidentialityImpact string  `json:"confidentialityImpact"`
						IntegrityImpact       string  `json:"integrityImpact"`
						AvailabilityImpact    string  `json:"availabilityImpact"`
						BaseScore             float64 `json:"baseScore"`
						BaseSeverity          string  `json:"baseSeverity"`
					} `json:"cvssV3"`
				} `json:"baseMetricV3"`
			} `json:"impact"`
		} `json:"CVE_Items"`
	} `json:"result"`
}

func checkIfCVExists(cveID string) (bool, error) {
	// URL for the NVD API
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cve/1.0/%s", cveID)

	// Make the API request
	resp, err := http.Get(url)
	if err != nil {
		return false, fmt.Errorf("error making API request: %v", err)
	}
	defer resp.Body.Close()

	// Decode the response
	var nvdResp NVDResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return false, fmt.Errorf("error decoding response: %v", err)
	}

	// Check if the response contains any results
	if nvdResp.TotalResults == 0 {
		return false, nil
	}

	return true, nil
}
