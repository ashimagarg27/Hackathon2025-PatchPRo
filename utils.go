package main

import (
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
