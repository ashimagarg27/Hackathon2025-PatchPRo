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

// Issue represents a GitHub issue.
type Issue struct {
	Number int     `json:"number"`
	Title  string  `json:"title"`
	Labels []Label `json:"labels"`
}

// GetIssuesWithLabel fetches issues from a repository with a specific label.
func GetIssuesWithLabel(owner, repo, label, token string) ([]Issue, error) {
	url := fmt.Sprintf("https://github.ibm.com/api/v3/repos/%s/%s/issues?labels=%s", owner, repo, label)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API error: %d %s\n%s", resp.StatusCode, resp.Status, body)
	}

	var issues []Issue
	if err := json.NewDecoder(resp.Body).Decode(&issues); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return issues, nil
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
