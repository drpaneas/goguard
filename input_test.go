package main

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestValidateCVE(t *testing.T) {
	validCases := []string{
		"CVE-2021-4238",
		"CVE-2022-0411",
		"CVE-2021-1234",
		"CVE-2022-5678",
	}

	invalidCases := []string{
		"CVE-20214238",
		"CVE-2021-4238sdf",
		"2021-4238",
		"GO-2022-0411",
		"",
	}

	for _, c := range validCases {
		_, err := validateCVE(c)
		if err != nil {
			t.Errorf("validateCVE(%s) returned error: %v, expected nil", c, err)
		}
	}

	for _, c := range invalidCases {
		_, err := validateCVE(c)
		if err == nil {
			t.Errorf("validateCVE(%s) returned nil, expected error", c)
		}
	}
}

func TestValidateURL(t *testing.T) {
	tests := []struct {
		url         string
		expectedURL string
		expectedErr error
	}{
		{"https://github.com/user/repo", "https://github.com/user/repo", nil},
		{"http://github.com/user/repo", "https://github.com/user/repo", nil},
		{"github.com/user/repo", "https://github.com/user/repo", nil},
		{"github.com/user/repo/", "https://github.com/user/repo", nil},
		{"https://not-github.com/user/repo", "", errors.New("invalid GitHub URL")},
	}

	for _, test := range tests {
		url, err := validateURL(test.url)
		assert.Equal(t, test.expectedURL, url)
		assert.Equal(t, test.expectedErr, err)
	}
}

func TestGetUserInput(t *testing.T) {
	os.Args = []string{"./test", "https://github.com/user/repo", "CVE-2021-4238"}
	cve, repoURL, err := getUserInput()
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	if cve != "CVE-2021-4238" {
		t.Errorf("Expected cve to be 'CVE-2021-4238', but got '%s'", cve)
	}
	if repoURL != "https://github.com/user/repo" {
		t.Errorf("Expected repoURL to be 'https://github.com/user/repo', but got '%s'", repoURL)
	}

	os.Args = []string{"./test", "this-is-not-a-url", "CVE-2021-4238"}
	_, _, err = getUserInput()
	if err == nil {
		t.Errorf("Expected error for invalid URL but got none")
	}

	os.Args = []string{"./test", "http://github.com/user/repo", "CVE-2021-4238"}
	cve, repoURL, err = getUserInput()
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	if cve != "CVE-2021-4238" {
		t.Errorf("Expected cve to be 'CVE-2021-4238', but got '%s'", cve)
	}
	if repoURL != "https://github.com/user/repo" {
		t.Errorf("Expected repoURL to be 'https://github.com/user/repo', but got '%s'", repoURL)
	}

	os.Args = []string{"./test", "https://github.com/user/repo"}
	_, _, err = getUserInput()
	if err == nil {
		t.Errorf("Expected error for missing CVE but got none")
	}

	os.Args = []string{"./test", "https://github.com/user/repo", "not-a-cve"}
	_, _, err = getUserInput()
	if err == nil {
		t.Errorf("Expected error for invalid CVE but got none")
	}
}
