package main

import (
	"encoding/json"
	"os"
	"strings"
	"time"
)

func isIssueDueWithin3Weeks(labels []Label) (bool, string) {
	now := time.Now()
	threeWeeks := now.AddDate(0, 0, 21)

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

func loadImageRepoMap(filename string) (map[string]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var imageRepoMap map[string]string
	err = json.NewDecoder(file).Decode(&imageRepoMap)
	return imageRepoMap, err
}

func extractImageNameFromIssueTitle(title string) string {
	// Format: vulnerable image: Image:Version (Cruisers)
	parts := strings.Split(title, ":")
	if len(parts) >= 2 {
		return strings.TrimSpace(parts[1])
	}
	return ""
}
