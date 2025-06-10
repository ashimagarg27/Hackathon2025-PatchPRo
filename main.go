package main

import (
	"fmt"
	"github.com/joho/godotenv"
	"log"
	"os"
	"patchpro/pkg/extractor"

	"strings"

	"patchpro/github"
	"patchpro/pkg/consts"
	"patchpro/pkg/loader"
	"patchpro/pkg/worker"
	"patchpro/slack"
)

func main() {
	// Load .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Use GITHUB_IBM_TOKEN for fetching issues from the compliance repository (GitHub Enterprise)
	ibmToken := os.Getenv("GITHUB_IBM_TOKEN")
	if ibmToken == "" || strings.TrimSpace(ibmToken) == "" {
		log.Fatal("GITHUB_IBM_TOKEN not set")
	}

	// Load image-to-repo mapping
	imageRepoMap, err := extractor.LoadImageRepoMap(consts.JsonFileName)
	if err != nil {
		log.Fatal(err)
	}

	// Skip fetching issues and generating cve_details.json; use the existing file
	issues, err := github.GetIssuesWithLabel(consts.ComplianceRepoOwner, consts.ComplianceRepoName, consts.StorageLabel, ibmToken)
	if err != nil {
		log.Fatalf("Error fetching compliance issues: %v", err)
	}
	fmt.Printf("Number of compliance Issues with label `%s`: %v \n\n", consts.StorageLabel, len(issues))

	//Generate CVE report and save to cve_details.json
	vulnImageCVEDataMap := extractor.GetImageCVEReport(issues, imageRepoMap, ibmToken)
	err = extractor.SaveMapToJSONFile(vulnImageCVEDataMap, "cve_details.json")
	if err != nil {
		log.Fatalf("Failed to save cve_details.json: %v", err)
	}

	// Load the CVE feed
	feed, err := loader.LoadRawFeed("cve_details.json")
	if err != nil {
		log.Fatalf("Failed to load cve_details.json: %v", err)
	}
	if len(feed) == 0 {
		log.Println("No CVE data found in cve_details.json")
	}

	// Patch CVE using worker-pool
	worker.Work(feed, imageRepoMap)

	// Push Slack notification
	if err := slack.SendSlackAlert("report"); err != nil {
		log.Printf("Failed to send Slack report: %v", err)
	}
}
