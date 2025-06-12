package github

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Label represents a GitHub label.
type Label struct {
	Name string `json:"name"`
}

// Comment represents a GitHub issue comment.
type Comment struct {
	Body string `json:"body"`
}

type Issue struct {
	Number      int       `json:"number"`
	Title       string    `json:"title"`
	HTMLURL     string    `json:"html_url"`
	PullRequest *struct{} `json:"pull_request,omitempty"`
	Labels      []Label   `json:"labels"`
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

// FetchComments fetches comments for a specific issue.
func FetchComments(owner, repo string, issueNumber int, token string) []Comment {
	url := fmt.Sprintf("https://github.ibm.com/api/v3/repos/%s/%s/issues/%d/comments", owner, repo, issueNumber)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("Failed to create request for comments: %v\n", err)
		return nil
	}

	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Failed to fetch comments for issue %d: %v\n", issueNumber, err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("GitHub API error: %d %s\n%s", resp.StatusCode, resp.Status, body)
		return nil
	}

	var comments []Comment
	if err := json.NewDecoder(resp.Body).Decode(&comments); err != nil {
		fmt.Printf("Failed to decode comments for issue %d: %v\n", issueNumber, err)
		return nil
	}

	return comments
}
