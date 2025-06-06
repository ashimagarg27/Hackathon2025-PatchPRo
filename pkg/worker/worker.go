package worker

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"patchpro/pkg/models"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
)

// Process executes the full remediation flow for a single repository plan.
func Process(ctx context.Context, j *models.Job) error {
	workDir, err := os.MkdirTemp("", "cvefix-*-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workDir)

	repo, err := git.PlainClone(workDir, false, &git.CloneOptions{
		URL:           j.Repo.URL,
		ReferenceName: plumbing.NewBranchReferenceName(j.Repo.DefaultBranch),
		Depth:         1,
	})
	if err != nil {
		return fmt.Errorf("git clone: %w", err)
	}

	branch := fmt.Sprintf("cvefix/%s", time.Now().Format("2006-01-02"))
	wt, _ := repo.Worktree()
	if err := wt.Checkout(&git.CheckoutOptions{Branch: plumbing.NewBranchReferenceName(branch), Create: true}); err != nil {
		return fmt.Errorf("checkout branch: %w", err)
	}

	// Apply patch ---------------------------------------------------------
	if err := patchRepo(workDir, j.Modules); err != nil {
		return err
	}

	// Bail early if nothing changed (clean worktree)
	status, _ := wt.Status()
	if status.IsClean() {
		return nil // already up‑to‑date
	}

	// Validate ------------------------------------------------------------
	if err := validate(workDir); err != nil {
		return err
	}

	// Commit & push -------------------------------------------------------
	sig := &object.Signature{Name: "cve‑bot", Email: "bot@example.com", When: time.Now()}
	wt.Add(".")
	wt.Commit("chore: fix CVEs", &git.CommitOptions{Author: sig})

	if err := repo.Push(&git.PushOptions{Auth: auth()}); err != nil && err != git.NoErrAlreadyUpToDate {
		return fmt.Errorf("git push: %w", err)
	}

	//_, err = openOrUpdatePR(ctx, branch, j)
	//if err != nil {
	//	return err
	//}

	return nil
}

func patchRepo(root string, mods []models.ModuleFix) error {
	if len(mods) > 0 {
		if err := bumpGoModules(root, mods); err != nil {
			return err
		}
	}
	// Dockerfile bumping can be added later when plan.Job carries image fixes.
	return nil
}

func bumpGoModules(dir string, list []models.ModuleFix) error {
	for _, m := range list {
		cmd := exec.Command("go", "get", fmt.Sprintf("%s@%s", m.Path, m.UpgradeTo))
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("go get %s: %v\n%s", m.Path, err, out)
		}
	}
	if out, err := exec.Command("go", "mod", "tidy").CombinedOutput(); err != nil {
		return fmt.Errorf("go mod tidy: %v\n%s", err, out)
	}
	return nil
}

// ------------------------------- validation ----------------------------------

func validate(dir string) error {
	if out, err := exec.Command("go", "vet", "./...").CombinedOutput(); err != nil {
		return fmt.Errorf("go vet failed:\n%s", out)
	}
	if out, err := exec.Command("go", "test", "./...").CombinedOutput(); err != nil {
		return fmt.Errorf("go test failed:\n%s", out)
	}
	return nil
}

//
//func openOrUpdatePR(ctx context.Context, branch string, j *models.Job) (string, error) {
//	owner, repo := splitOwnerRepo(j.Repo.URL)
//	gh := github.NewTokenClient(ctx, os.Getenv("GITHUB_TOKEN"))
//
//	// Reuse PR if already open
//	prs, _, _ := gh.PullRequests.List(ctx, owner, repo, &github.PullRequestListOptions{Head: owner + ":" + branch, State: "open"})
//	if len(prs) > 0 {
//		return prs[0].GetHTMLURL(), nil
//	}
//
//	title := "fix: remediate CVEs automatically"
//	body := prBody(j)
//	base := j.Repo.DefaultBranch
//	pr, _, err := gh.PullRequests.Create(ctx, owner, repo, &github.NewPullRequest{Title: &title, Head: &branch, Base: &base, Body: body})
//	if err != nil {
//		return "", err
//	}
//
//	// Label for easy triage
//	_, _, _ = gh.Issues.AddLabelsToIssue(ctx, owner, repo, pr.GetNumber(), []string{"security", "cve"})
//	return pr.GetHTMLURL(), nil
//}

func prBody(j *models.Job) *string {
	var sb strings.Builder
	sb.WriteString("### CVEs fixed\n\n| Package | New version | CVEs |\n|---|---|---|\n")
	for _, m := range j.Modules {
		sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", m.Path, m.UpgradeTo, strings.Join(m.CVEs, ", ")))
	}
	s := sb.String()
	return &s
}

func auth() *githttp.BasicAuth {
	return &githttp.BasicAuth{Username: "x-access-token", Password: os.Getenv("GITHUB_TOKEN")}
}

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func splitOwnerRepo(url string) (owner, repo string) {
	url = strings.TrimSuffix(url, ".git")
	parts := strings.Split(url, "/")
	n := len(parts)
	if n >= 2 {
		owner, repo = parts[n-2], parts[n-1]
	}
	return
}
