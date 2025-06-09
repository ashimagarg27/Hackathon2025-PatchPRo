package pr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func GetBaseURL(repoURL string) string {
	if strings.Contains(repoURL, "github.ibm.com") {
		return "https://github.ibm.com/api/v3/"
	}
	return "https://api.github.com/"
}

func CreatePR(repoOwner, repoName, baseBranch, headBranch, title, body, token string, repoURL string) error {
	baseURL := GetBaseURL(repoURL)
	url := fmt.Sprintf("%s/repos/%s/%s/pulls", baseURL, repoOwner, repoName)

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
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("PR creation failed (%d): %s", resp.StatusCode, string(bodyBytes))
	}
	return nil
}
