package worker

import (
	"golang.org/x/mod/semver"
	"patchpro/pkg/models"
	"sort"
	"strings"
	"time"
)

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

// ------------------------ HELPER METHODS --------------------------

// toModuleFixes normalises entries for a single repo: deduplicates packages,
// merges CVE lists, and chooses the *highest* fixed version among the
// remediation ranges.
func toModuleFixes(entries []models.CVEDetails) []models.ModuleFix {
	byPkg := map[string]*models.ModuleFix{}

	for _, e := range entries {
		fixed := lastFixedVersion(e.Remediation)
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

// lastFixedVersion grabs the last token after the last ">=" and strips
// commas/spaces → returns a semver-compatible string.
func lastFixedVersion(text string) string {
	parts := strings.Split(text, ">=")
	if len(parts) == 0 {
		return ""
	}
	seg := parts[len(parts)-1]
	tokens := strings.FieldsFunc(seg, func(r rune) bool { return r == ',' || r == ' ' })
	if len(tokens) == 0 {
		return ""
	}
	v := tokens[len(tokens)-1]
	if v != "" && v[0] != 'v' {
		v = "v" + v
	}
	return v
}
