package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"sort"
	"strings"
	"time"
	"fmt"

	"github.com/joho/godotenv"
	"golang.org/x/mod/semver"

	"patchpro/pkg/consts"
	"patchpro/pkg/models"
	"patchpro/pkg/worker"
	"patchpro/slack"
	"patchpro/utils"
	"patchpro/github"
)

// LoadRawFeed reads the JSON file at path and unmarshals into RawFeed.
func LoadRawFeed(path string) (models.RawFeed, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var rf models.RawFeed
	if err := json.Unmarshal(b, &rf); err != nil {
		return nil, err
	}

	return rf, nil
}

// firstFixedVersion grabs the first token after the last ">=" and strips
// commas/spaces → returns a semver-compatible string.
func firstFixedVersion(text string) string {
	parts := strings.Split(text, ">=")
	if len(parts) == 0 {
		return ""
	}
	seg := parts[len(parts)-1]
	tokens := strings.FieldsFunc(seg, func(r rune) bool { return r == ',' || r == ' ' })
	if len(tokens) == 0 {
		return ""
	}
	v := tokens[0]
	if v != "" && v[0] != 'v' {
		v = "v" + v
	}
	return v
}

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
	imageRepoMap, err := utils.LoadImageRepoMap(consts.JsonFileName)
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
	vulnImageCVEDataMap := utils.GetImageCVEReport(issues, imageRepoMap, ibmToken)
	err = utils.SaveMapToJSONFile(vulnImageCVEDataMap, "cve_details.json")
	if err != nil {
	log.Fatalf("Failed to save cve_details.json: %v", err)
	}

	// Load the CVE feed
	feed, err := LoadRawFeed("cve_details.json")
	if err != nil {
		log.Fatalf("Failed to load cve_details.json: %v", err)
	}
	if len(feed) == 0 {
		log.Println("No CVE data found in cve_details.json")
	}

	// Loop through every repo in feed
	issueNum := 1000
	for key, repoURL := range imageRepoMap {
		log.Printf("Processing image: %s", key)
		if _, ok := feed[key]; !ok {
			log.Printf("Skipping %s: not found in CVE feed", key)
			continue
		}

		// Declare cveFeed only if the key exists
		cveFeed := feed[key]
		repoURL, branch := splitURL(repoURL)
		log.Printf("Repo URL: %s, Default Branch: %s", repoURL, branch)
		job, err := BuildJob(cveFeed, repoURL, branch, issueNum)
		if err != nil {
			log.Printf("skip %s: %v", key, err)
			continue
		}
		if job == nil {
			log.Printf("%s already up-to-date", key)
			continue
		}

		log.Printf("Processing job for %s with %d modules", key, len(job.Modules))
		if err := worker.Process(context.Background(), job); err != nil {
			log.Printf("worker failed for %s: %v", key, err)
		} else {
			log.Printf("Successfully processed %s", key)
			issueNum++
		}
	}

	if err := slack.SendSlackAlert("report"); err != nil {
		log.Printf("Failed to send Slack report: %v", err)
	}
}

// toModuleFixes normalises entries for a single repo: deduplicates packages,
// merges CVE lists, and chooses the *highest* fixed version among the
// remediation ranges.
func toModuleFixes(entries []models.CVEDetails) []models.ModuleFix {
	byPkg := map[string]*models.ModuleFix{}

	for _, e := range entries {
		fixed := firstFixedVersion(e.Remediation)
		if fixed == "" {
			continue // malformed remediation string → skip
		}

		mf, ok := byPkg[e.Package]
		if !ok {
			mf = &models.ModuleFix{Path: e.Package, UpgradeTo: fixed, CVEs: []string{e.CVEID}}
			byPkg[e.Package] = mf
			continue
		}
		mf.CVEs = append(mf.CVEs, e.CVEID)
		if semver.Compare(fixed, mf.UpgradeTo) > 0 {
			mf.UpgradeTo = fixed
		}
	}

	list := make([]models.ModuleFix, 0, len(byPkg))
	for _, v := range byPkg {
		sort.Strings(v.CVEs)
		list = append(list, *v)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Path < list[j].Path })
	return list
}

// BuildJob constructs a Job for a single repo, using the CVE feed directly.
func BuildJob(cveFeed models.CVEFeed, repoURL, branch string, issueNum int) (*models.Job, error) {
	mods := toModuleFixes(cveFeed.CVEsData)
	if len(mods) == 0 {
		return nil, nil // no fixes needed
	}

	j := &models.Job{Modules: mods}
	j.Repo.URL = repoURL
	// Since we're pushing directly to the same repo, UpstreamURL is the same as URL
	j.Repo.UpstreamURL = repoURL

	if branch == "" {
		branch = "master"
	}

	j.Repo.DefaultBranch = branch
	j.Issue.Number = issueNum
	j.Issue.Due = time.Now().AddDate(0, 0, 21) // three weeks out by default

	return j, nil
}

func splitURL(in string) (url, branch string) {
	parts := strings.Split(in, "/tree/")

	url = in
	branch = "master"

	if len(parts) == 2 {
		url = parts[0]
		branch = parts[1]
	}

	// Ensure URL ends with .git for go-git clone convenience
	if !strings.HasSuffix(url, ".git") {
		url += ".git"
	}

	return
}
