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

	vulnImageCVEDataMap := getImageCVEReport(complianceIssues, imageReoMap, token)
	report := formatCVEsAsReadableString(vulnImageCVEDataMap)
	fmt.Print(report)

	err = saveMapToJSONFile(vulnImageCVEDataMap, "cve_details.json")
	if err != nil {
		fmt.Println("Failed to save JSON:", err)
	}

	SendSlackAlert(report)

	if err := createTestPR(token); err != nil {
		log.Printf("PR creation failed: %v", err)
	} else {
		log.Println("Test PR created successfully!")
	}

}
