package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

func createPR(repoOwner, repoName, baseBranch, headBranch, title, body, token string) error {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls", repoOwner, repoName)
	prData := map[string]string{
		"title": title,
		"body":  body,
		"head":  headBranch,
		"base":  baseBranch,
	}

	jsonData, _ := json.Marshal(prData)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("PR creation failed: %s", resp.Status)
	}

	return nil
}

func createTestPR(token string) error {
	return createPR(
		"ashima",
		"Hackathon2025-PatchPRo",
		"main",
		"prachi",
		"Test PR from PatchPro",
		"This is a test PR created by the PatchPro tool",
		token,
	)
}
