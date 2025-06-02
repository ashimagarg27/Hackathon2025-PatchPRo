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

	// Load image-to-repo map from JSON
	imageReoMap, err := loadImageRepoMap(JsonFileName)
	if err != nil {
		panic(err)
	}

	// Scan compliance repo to fetch issues with storage label
	complianceIssues, err := GetIssuesWithLabel(ComplianceRepoOwner, ComplianceRepoName, StorageLabel, token)
	if err != nil {
		log.Fatalf("Error fetching compliance issues: %v", err)
	}
	fmt.Printf("Number of compliance Issues with label `%s`: %v \n\n", StorageLabel, len(complianceIssues))

	noOfDueIssues := 0
	var requiredIssues []Issue
	for _, issue := range complianceIssues {
		if ok, _ := isIssueDueWithin3Weeks(issue.Labels); ok {
			image := extractImageNameFromIssueTitle(issue.Title)
			if _, exists := imageReoMap[image]; exists {
				requiredIssues = append(requiredIssues, issue)
			}
			noOfDueIssues++
		}
	}
	fmt.Printf("Number of compliance Issues with due date within 3 weeks : %v \n\n", noOfDueIssues)
	fmt.Printf("Number of required compliance Issues need to be fixed : %v \n\n", len(requiredIssues))
}
