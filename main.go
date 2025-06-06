package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"golang.org/x/mod/semver"

	"patchpro/github"
	"patchpro/pkg/consts"
	"patchpro/pkg/models"
	"patchpro/pkg/worker"
	"patchpro/slack"
	"patchpro/utils"
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
	// take the substring after the last">
	seg := parts[len(parts)-1]
	// tokenize on comma/space
	tokens := strings.FieldsFunc(seg, func(r rune) bool { return r == ',' || r == ' ' })
	if len(tokens) == 0 {
		return ""
	}
	v := tokens[0]
	// ensure it starts with "v" for semver library
	if v != "" && v[0] != 'v' {
		v = "v" + v
	}
	return v
}

func main() {
	//Load .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" || strings.TrimSpace(token) == "" {
		log.Fatal("GITHUB_TOKEN not set")
	}

	imageRepoMap, err := utils.LoadImageRepoMap(consts.JsonFileName)
	if err != nil {
		log.Fatal(err)
	}

	// Scan compliance repo to fetch issues with storage label
	complianceIssues, err := github.GetIssuesWithLabel(consts.ComplianceRepoOwner, consts.ComplianceRepoName, consts.StorageLabel, token)
	if err != nil {
		log.Fatalf("Error fetching compliance issues: %v", err)
	}

	fmt.Printf("Number of compliance Issues with label `%s`: %v \n\n", consts.StorageLabel, len(complianceIssues))

	//vulnImageCVEDataMap := utils.GetImageCVEReport(complianceIssues, imageRepoMap, token)
	//report := utils.FormatCVEsAsReadableString(vulnImageCVEDataMap)
	//
	//fmt.Print(report)
	//
	//err = utils.SaveMapToJSONFile(vulnImageCVEDataMap, "cve_details.json")
	//if err != nil {
	//	fmt.Println("Failed to save JSON:", err)
	//}

	feed, _ := LoadRawFeed("cve_details.json")

	// 4. loop through every repo in feed
	issueNum := 1000
	for key, urlWithBranch := range imageRepoMap {
		// we only care if the key is in the CVE feed
		if _, ok := feed[key]; !ok {
			continue
		}

		// split URL and default branch (expects .../tree/<branch>)
		url, branch := splitURL(urlWithBranch)
		job, err := BuildJob(feed, key, url, branch, issueNum)
		if err != nil {
			log.Printf("skip %s: %v", key, err)
			continue
		}
		if job == nil {
			log.Printf("%s already up‑to‑date", key)
			continue
		}

		if err := worker.Process(context.Background(), job); err != nil {
			log.Printf("worker failed for %s: %v", key, err)
		} else {
			issueNum++
		}
	}

	slack.SendSlackAlert("report")
}

// toModuleFixes normalises entries for a single repo: deduplicates packages,
// merges CVE lists, and chooses the *highest* fixed version among the
// remediation ranges.
func toModuleFixes(entries []models.CVEEntry) []models.ModuleFix {
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

// BuildJob constructs a Job for a single repo name, using a repo→URL mapping
// and default branch ("main" unless overridden).
func BuildJob(raw models.RawFeed, repoName string, repoURL string, branch string, issueNum int) (*models.Job, error) {
	entries, ok := raw[repoName]
	if !ok {
		return nil, fmt.Errorf("repo %s not found in feed", repoName)
	}

	mods := toModuleFixes(entries)
	j := &models.Job{Modules: mods}
	j.Repo.URL = repoURL
	
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

	// ensure URL ends with .git for go-git clone convenience
	if !strings.HasSuffix(url, ".git") {
		url += ".git"
	}

	return
}
