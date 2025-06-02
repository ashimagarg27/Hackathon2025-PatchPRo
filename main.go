package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

func main() {
	// Load .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" || strings.TrimSpace(token) == "" {
		log.Fatal("GITHUB_TOKEN not set")
	}

	// Scan compliance repo to fetch issues with storage label
	complianceIssues, err := GetIssuesWithLabel(ComplianceRepoOwner, ComplianceRepoName, StorageLabel, token)
	if err != nil {
		log.Fatalf("Error fetching compliance issues: %v", err)
	}
	fmt.Printf("Number of compliance Issues with %s label: %v \n\n", StorageLabel, len(complianceIssues))

	// for _, issue := range complianceIssues {
	// 	fmt.Printf("#%d: %s\nURL: %s\n\n", issue.Number, issue.Title, issue.HTMLURL)
	// }
}
