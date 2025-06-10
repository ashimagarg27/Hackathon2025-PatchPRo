package worker

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"patchpro/pkg/models"
	"patchpro/pkg/pullrequest"
	"patchpro/slack"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
)

// cacheDir for local clones
var cacheDir = "/var/lib/cvebot/repos"

// Process executes the full remediation flow for a single repository plan.
func Process(j *models.Job) error {
	slug := filepath.Base(strings.TrimSuffix(j.Repo.URL, ".git"))
	path := filepath.Join(cacheDir, slug)
	repo, err := ensureRepo(path, j.Repo.URL, j.Repo.DefaultBranch)
	if err != nil {
		return fmt.Errorf("ensure repo: %w", err)
	}

	branch := fmt.Sprintf("cvefix/%s", time.Now().Format("2006-01-02"))
	log.Printf("Checking out new branch: %s", branch)

	wt, _ := repo.Worktree()
	if err := wt.Checkout(&git.CheckoutOptions{Branch: plumbing.NewBranchReferenceName(branch), Create: true}); err != nil {
		return fmt.Errorf("checkout branch: %w", err)
	}

	// Apply patch
	log.Printf("Applying patches for %d modules", len(j.Modules))
	if err := patchRepo(path, j.Modules); err != nil {
		return err
	}

	// Bail early if nothing changed (clean worktree)
	{
		if status, _ := wt.Status(); status.IsClean() {
			log.Printf("No changes applied for %s", j.Repo.URL)
			return nil // already up-to-date
		}
	}

	// Validate
	{
		log.Printf("Running validation (go vet, go test)")
		if err := validate(path); err != nil {
			return err
		}
	}

	// Commit & push
	{
		sig := &object.Signature{Name: "cve-bot", Email: "bot@example.com", When: time.Now()}
		log.Printf("Committing changes")
		wt.Add(".")
		wt.Commit("chore: fix CVEs", &git.CommitOptions{Author: sig})

		log.Printf("Pushing to %s, Branch: %s", j.Repo.URL, branch)
		if err := repo.Push(&git.PushOptions{Auth: auth(j.Repo.URL)}); err != nil && err != git.NoErrAlreadyUpToDate {
			return fmt.Errorf("git push: %w", err)
		}
	}

	// Create PR
	{
		owner, repoName := splitOwnerRepo(j.Repo.UpstreamURL)
		baseBranch := j.Repo.DefaultBranch
		headBranch := branch // Same repo, just the new branch
		title := "fix: remediate CVEs automatically"

		bodyPtr := prBody(j)
		bodyStr := *bodyPtr
		log.Printf("Creating PR in repo: %s", j.Repo.UpstreamURL)

		prURL, err := pullrequest.CreatePR(owner, repoName, baseBranch, headBranch, title, bodyStr, j.Repo.UpstreamURL)
		if err != nil {
			log.Printf("Failed to create PR for %s: %v", j.Repo.URL, err)
			slack.AddReportItem(j.Repo.URL, getCVEs(j), "Failed to create PR: "+err.Error(), "")
		} else {
			log.Printf("PR created successfully for %s: %s", j.Repo.URL, prURL)
			slack.AddReportItem(j.Repo.URL, getCVEs(j), "PR created", prURL)
		}
	}

	return nil
}

func getCVEs(j *models.Job) []string {
	var cves []string
	for _, m := range j.Modules {
		cves = append(cves, m.CVEs...)
	}
	return cves
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

func bumpGoModules(root string, mods []models.ModuleFix) error {
	for _, m := range mods {
		if !isGoModule(m.Path) {
			log.Printf("Skipping non-Go package %s for upgrade", m.Path)
			continue
		}
		log.Printf("Upgrading %s to %s", m.Path, m.UpgradeTo)
		cmd := exec.Command("go", "get", fmt.Sprintf("%s@%s", m.Path, m.UpgradeTo))
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("go get %s: %v\n%s", m.Path, err, out)
		}
	}
	log.Printf("Running go mod tidy")
	if out, err := exec.Command("go", "mod", "tidy").CombinedOutput(); err != nil {
		return fmt.Errorf("go mod tidy: %v\n%s", err, out)
	}
	return nil
}

// isGoModule checks if a package path is a valid Go module path.
func isGoModule(path string) bool {
	// Go module paths typically contain a dot (e.g., github.com/..., golang.org/...)
	// System libraries like glibc, krb5-libs, libgcc do not.
	return strings.Contains(path, ".") && !strings.HasPrefix(path, "glibc") && !strings.HasPrefix(path, "krb5-libs") && !strings.HasPrefix(path, "libgcc")
}

func validate(dir string) error {
	if out, err := exec.Command("go", "vet", "./...").CombinedOutput(); err != nil {
		return fmt.Errorf("go vet failed:\n%s", out)
	}
	if out, err := exec.Command("go", "test", "./...").CombinedOutput(); err != nil {
		return fmt.Errorf("go test failed:\n%s", out)
	}
	return nil
}

func prBody(j *models.Job) *string {
	var sb strings.Builder
	sb.WriteString("### CVEs fixed\n\n| Package | New version | CVEs |\n|---|---|---|\n")
	for _, m := range j.Modules {
		if isGoModule(m.Path) { // Only include Go modules in PR body
			sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", m.Path, m.UpgradeTo, strings.Join(m.CVEs, ", ")))
		}
	}
	s := sb.String()
	if s == "### CVEs fixed\n\n| Package | New version | CVEs |\n|---|---|---|\n" {
		s = "No Go modules updated. System library updates may be required manually."
	}
	return &s
}

func auth(repoURL string) *githttp.BasicAuth {
	token := pullrequest.GetToken(repoURL)
	return &githttp.BasicAuth{Username: "x-access-token", Password: token}
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

func ensureRepo(path, url, branch string) (*git.Repository, error) {
	auth := basicAuth() // your helper that returns *githttp.BasicAuth

	// If already cloned, just fetch + checkout
	if fi, err := os.Stat(filepath.Join(path, ".git")); err == nil && fi.IsDir() {
		r, err := git.PlainOpen(path)
		if err != nil {
			return nil, err
		}
		// Fetch the latest refs over HTTPS with auth
		err = r.Fetch(&git.FetchOptions{
			RemoteName: "origin",
			Depth:      1,
			Force:      true,
			Auth:       auth,
		})
		if err != nil && err != git.NoErrAlreadyUpToDate {
			return nil, fmt.Errorf("git fetch: %w", err)
		}
		wt, err := r.Worktree()
		if err != nil {
			return nil, err
		}
		if err := wt.Checkout(&git.CheckoutOptions{
			Branch: plumbing.NewBranchReferenceName(branch),
			Force:  true,
		}); err != nil {
			return nil, err
		}
		return r, nil
	}

	// First-time clone also needs auth
	return git.PlainClone(path, false, &git.CloneOptions{
		URL:           url,
		Depth:         1,
		ReferenceName: plumbing.NewBranchReferenceName(branch),
		Auth:          auth,
	})
}

func basicAuth() *githttp.BasicAuth {
	return &githttp.BasicAuth{
		Username: "x-access-token",              // can be anything non-empty
		Password: os.Getenv("GITHUB_IBM_TOKEN"), // your PAT
	}
}
