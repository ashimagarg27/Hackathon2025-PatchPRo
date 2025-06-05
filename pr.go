package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func createPR(repoOwner, repoName, baseBranch, headBranch, title, body, token string) error {
	// Use public GitHub endpoint
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls", repoOwner, repoName)

	prData := map[string]interface{}{
		"title": title,
		"body":  body,
		"head":  headBranch,
		"base":  baseBranch,
	}

	jsonData, _ := json.Marshal(prData)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// Headers for public GitHub
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("PR creation failed (%d): %s", resp.StatusCode, string(body))
	}
	return nil
}

func createTestPR(token string) error {
	return createPR(
		"ashimagarg27",
		"Hackathon2025-PatchPRo",
		"main",
		"prachi-test2",
		"Test PR from PatchPro",
		"This is a test PR created by the PatchPro tool",
		token,
	)
}
