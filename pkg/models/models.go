package models

import "time"

// CVEDetails represents a single CVE entry in the feed.
type CVEDetails struct {
	CVEID       string `json:"cve_id"`
	Package     string `json:"package"`
	Remediation string `json:"remediation"`
}

// CVEFeed represents the CVE data for a single repository.
type CVEFeed struct {
	DueDate  string       `json:"DueDate"`
	CVEsData []CVEDetails `json:"CVEsData"`
}

// RawFeed is a map of repository names to their CVE data.
type RawFeed map[string]CVEFeed

// ModuleFix describes a single module to be upgraded.
type ModuleFix struct {
	Path      string
	UpgradeTo string
	CVEs      []string
}

// Repo describes a single repository.
type Repo struct {
	URL           string
	UpstreamURL   string
	DefaultBranch string
}

// Issue describes an issue in a repository.
type Issue struct {
	Number int
	Due    time.Time
}

// Job describes a single remediation plan for a repository.
type Job struct {
	Modules []ModuleFix
	Repo    Repo
	Issue   Issue
}
