package extractor

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"patchpro/github"
	"patchpro/pkg/consts"
	"patchpro/pkg/models"
	"patchpro/utils"
)

func isIssueDueWithin3Weeks(labels []github.Label) (bool, string) {
	now := time.Now()
	threeWeeks := now.AddDate(0, 0, 100)

	for _, label := range labels {
		if strings.HasPrefix(label.Name, "due:") {
			dateStr := strings.TrimPrefix(label.Name, "due:")
			dueDate, err := time.Parse("2006-01-02", dateStr)
			if err == nil && dueDate.After(now) && dueDate.Before(threeWeeks) {
				return true, dateStr
			}
		}
	}
	return false, ""
}

func extractCVEsFromIssueComments(comment string) []models.CVEDetails {
	var cves []models.CVEDetails

	cveRegex := regexp.MustCompile(`(?s)(CVE-\d{4}-\d+).*?Vulnerable package:\s*([^\n]+).*?Corrective action:\s*([^\n]+)`)
	matches := cveRegex.FindAllStringSubmatch(comment, -1)

	for _, match := range matches {
		cves = append(cves, models.CVEDetails{
			CVEID:       utils.Clean(match[1]),
			Package:     utils.Clean(match[2]),
			Remediation: utils.Clean(match[3]),
		})
	}

	return cves
}

func LoadImageRepoMap(filename string) (map[string]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var imageRepoMap map[string]string
	err = json.NewDecoder(file).Decode(&imageRepoMap)
	return imageRepoMap, err
}

func GetImageCVEReport(issues []github.Issue, imageReoMap map[string]string, token string) map[string]models.CVEFeed {
	noOfDueIssues := 0
	noOfReqIssues := 0
	vulnImageCVEDataMap := make(map[string]models.CVEFeed)
	for _, issue := range issues {
		if ok, dueDate := isIssueDueWithin3Weeks(issue.Labels); ok {
			image := utils.ExtractImageNameFromIssueTitle(issue.Title)
			if _, exists := imageReoMap[image]; exists {
				comments := github.FetchComments(consts.ComplianceRepoOwner, consts.ComplianceRepoName, issue.Number, token)
				for _, comment := range comments {
					cves := extractCVEsFromIssueComments(comment.Body)
					if len(cves) == 0 {
						continue
					}

					if _, exists := vulnImageCVEDataMap[image]; !exists {
						vulnImageCVEDataMap[image] = models.CVEFeed{
							DueDate:  dueDate,
							CVEsData: []models.CVEDetails{},
						}
					}

					existingData := vulnImageCVEDataMap[image].CVEsData
					existingCVEsInMap := make(map[string]bool)

					for _, c := range existingData {
						key := c.CVEID + "::" + c.Package
						existingCVEsInMap[key] = true
					}

					for _, newCVE := range cves {
						key := newCVE.CVEID + "::" + newCVE.Package
						if !existingCVEsInMap[key] {
							existingData = append(existingData, newCVE)
							existingCVEsInMap[key] = true
						}
					}

					vulnImageCVEDataMap[image] = models.CVEFeed{
						DueDate:  dueDate,
						CVEsData: existingData,
					}
				}
				noOfReqIssues++
			}
			noOfDueIssues++
		}
	}
	fmt.Printf("Number of compliance Issues with due date within 3 weeks : %v \n\n", noOfDueIssues)
	fmt.Printf("Number of required compliance Issues need to be fixed : %v \n\n", noOfReqIssues)

	return vulnImageCVEDataMap
}

func FormatCVEsAsReadableString(data map[string]models.CVEFeed) string {
	var sb strings.Builder
	for image, cveList := range data {
		sb.WriteString(fmt.Sprintf("Image: %s\n", image))
		sb.WriteString(fmt.Sprintf("Due Date: %s\n", cveList.DueDate))
		for _, cve := range cveList.CVEsData {
			sb.WriteString(fmt.Sprintf("  - CVE: %s\n", cve.CVEID))
			sb.WriteString(fmt.Sprintf("    Package: %s\n", cve.Package))
			sb.WriteString(fmt.Sprintf("    Remediation: %s\n", cve.Remediation))
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

func SaveMapToJSONFile(data map[string]models.CVEFeed, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")

	return encoder.Encode(data)
}
