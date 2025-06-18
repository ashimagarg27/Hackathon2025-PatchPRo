package utils

import (
	"strings"
)

func ExtractImageNameFromIssueTitle(title string) string {
	// Format: vulnerable image: Image:Version (Cruisers)
	parts := strings.Split(title, ":")
	if len(parts) >= 2 {
		return strings.TrimSpace(parts[1])
	}
	return ""
}

func Clean(s string) string {
	return strings.Trim(strings.ReplaceAll(s, "**", ""), " \n")
}

func SplitURL(in string) (url, branch string) {
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
