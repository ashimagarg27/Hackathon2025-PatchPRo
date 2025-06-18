package pullrequest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

func getBaseURL(repoURL string) string {
	if strings.Contains(repoURL, "github.ibm.com") {
		return "https://github.ibm.com/api/v3"
	}
	return "https://api.github.com"
}

func GetToken(repoURL string) string {
	if strings.Contains(repoURL, "github.ibm.com") {
		return os.Getenv("GITHUB_IBM_TOKEN")
	}

	return os.Getenv("GITHUB_PUBLIC_TOKEN")
}

func CreatePR(repoOwner, repoName, baseBranch, headBranch, title, body, repoURL string) (string, error) {
	baseURL := getBaseURL(repoURL)
	token := GetToken(repoURL)
	url := fmt.Sprintf("%s/repos/%s/%s/pulls", baseURL, repoOwner, repoName)

	// Log request details for debugging
	log.Printf("Creating PR for repo: %s/%s, URL: %s, Base: %s, Head: %s", repoOwner, repoName, url, baseBranch, headBranch)

	prData := map[string]interface{}{
		"title": title,
		"body":  body,
		"head":  headBranch,
		"base":  baseBranch,
	}

	jsonData, err := json.Marshal(prData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal PR data: %v", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("PR creation failed (%d): %s", resp.StatusCode, string(bodyBytes))
	}

	var prResponse struct {
		HTMLURL string `json:"html_url"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&prResponse); err != nil {
		return "", fmt.Errorf("failed to decode PR response: %v", err)
	}

	return prResponse.HTMLURL, nil
}
