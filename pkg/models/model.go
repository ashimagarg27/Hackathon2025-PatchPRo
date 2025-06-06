package models

import "time"

type CVEEntry struct {
	CVEID       string `json:"CVEID"`
	Package     string `json:"Package"`
	Remediation string `json:"Remediation"`
}

type RawFeed map[string][]CVEEntry

type Job struct {
	Repo struct {
		URL           string `json:"url"`
		DefaultBranch string `json:"default_branch"`
	} `json:"repo"`
	Issue struct {
		Number int       `json:"number"`
		Due    time.Time `json:"due"`
	} `json:"issue"`
	Modules []ModuleFix `json:"modules"`
	//Images  []ImageFix  `json:"images"`
}

type ModuleFix struct {
	Path      string   `json:"path"`
	UpgradeTo string   `json:"upgradeTo"`
	CVEs      []string `json:"cves"`
}

type ImageFix struct {
	From      string   `json:"from"`
	UpgradeTo string   `json:"upgradeTo"`
	CVEs      []string `json:"cves"`
}
