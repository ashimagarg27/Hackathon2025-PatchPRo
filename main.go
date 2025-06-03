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

	for image, cveData := range vulnImageCVEDataMap {
		fmt.Println("Vuln Image: ", image)
		fmt.Println("CVE Details: ")

		for _, cve := range cveData {
			fmt.Println("   ", "CVE ID: ", cve.CVEID)
			fmt.Println("   ", "Package: ", cve.Package)
			fmt.Println("   ", "Remediation: ", cve.Remediation)
			fmt.Println()
		}
	}

	SendSlackAlert(formatCVEsAsReadableString(vulnImageCVEDataMap))
}
