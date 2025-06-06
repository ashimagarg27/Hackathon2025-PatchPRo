package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"patchpro/github"
	"patchpro/pkg/consts"
	"regexp"
	"strings"
	"time"
)

type CVEDetails struct {
	CVEID       string `json:"cve_id"`
	Package     string `json:"package"`
	Remediation string `json:"remediation"`
}

type VulnImageData struct {
	DueDate  string
	CVEsData []CVEDetails
}

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

func extractImageNameFromIssueTitle(title string) string {
	// Format: vulnerable image: Image:Version (Cruisers)
	parts := strings.Split(title, ":")
	if len(parts) >= 2 {
		return strings.TrimSpace(parts[1])
	}
	return ""
}

func clean(s string) string {
	return strings.Trim(strings.ReplaceAll(s, "**", ""), " \n")
}

func extractCVEsFromIssueComments(comment string) []CVEDetails {
	var cves []CVEDetails

	cveRegex := regexp.MustCompile(`(?s)(CVE-\d{4}-\d+).*?Vulnerable package:\s*([^\n]+).*?Corrective action:\s*([^\n]+)`)
	matches := cveRegex.FindAllStringSubmatch(comment, -1)

	for _, match := range matches {
		cves = append(cves, CVEDetails{
			CVEID:       clean(match[1]),
			Package:     clean(match[2]),
			Remediation: clean(match[3]),
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

func GetImageCVEReport(issues []github.Issue, imageReoMap map[string]string, token string) map[string]VulnImageData {
	noOfDueIssues := 0
	noOfReqIssues := 0
	// requiredImageIssuesMap := make(map[string][]Issue)
	vulnImageCVEDataMap := make(map[string]VulnImageData)
	for _, issue := range issues {
		if ok, dueDate := isIssueDueWithin3Weeks(issue.Labels); ok {
			image := extractImageNameFromIssueTitle(issue.Title)
			if _, exists := imageReoMap[image]; exists {
				// if _, exists := requiredImageIssuesMap[image]; !exists {
				// 	requiredImageIssuesMap[image] = []Issue{}
				// }
				// requiredImageIssuesMap[image] = append(requiredImageIssuesMap[image], issue)

				comments := github.FetchComments(consts.ComplianceRepoName, consts.ComplianceRepoName, issue.Number, token)
				for _, comment := range comments {
					cves := extractCVEsFromIssueComments(comment.Body)
					if len(cves) == 0 {
						continue
					}

					if _, exists := vulnImageCVEDataMap[image]; !exists {
						vulnImageCVEDataMap[image] = VulnImageData{
							DueDate:  dueDate,
							CVEsData: []CVEDetails{},
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

					vulnImageCVEDataMap[image] = VulnImageData{
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

func FormatCVEsAsReadableString(data map[string]VulnImageData) string {
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

func SaveMapToJSONFile(data map[string]VulnImageData, filename string) error {
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
