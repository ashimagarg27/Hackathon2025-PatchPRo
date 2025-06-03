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
	Labels      []Label   `json:"labels"`
}

type Label struct {
	Name string `json:"name"`
}

type Comment struct {
	Body string `json:"body"`
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

func FetchComments(owner, repo string, issueNumber int, token string) []Comment {
	url := fmt.Sprintf("https://api.github.ibm.com/repos/%s/%s/issues/%d/comments", owner, repo, issueNumber)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("GitHub API error: %s\n%s\n", resp.Status, string(body))
		panic("GitHub API returned non-200 status")
	}

	var comments []Comment
	if err := json.NewDecoder(resp.Body).Decode(&comments); err != nil {
		panic(err)
	}
	return comments
}
