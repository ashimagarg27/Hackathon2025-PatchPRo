package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type Issue struct {
	Number      int       `json:"number"`
	Title       string    `json:"title"`
	HTMLURL     string    `json:"html_url"`
	PullRequest *struct{} `json:"pull_request,omitempty"`
}

func GetIssuesWithLabel(owner, repo, label, token string) ([]Issue, error) {
	var allIssues []Issue
	page := 1

	for {
		url := fmt.Sprintf("https://api.github.ibm.com/repos/%s/%s/issues?state=open&labels=%s&per_page=100&page=%d", owner, repo, label, page)
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Authorization", "token "+token)
		req.Header.Set("Accept", "application/vnd.github+json")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("GitHub API error: %s\n%s", resp.Status, string(body))
		}

		var issues []Issue
		if err := json.NewDecoder(resp.Body).Decode(&issues); err != nil {
			return nil, err
		}

		if len(issues) == 0 {
			break
		}

		for _, issue := range issues {
			if issue.PullRequest == nil {
				allIssues = append(allIssues, issue)
			}
		}

		page++
	}

	return allIssues, nil
}
