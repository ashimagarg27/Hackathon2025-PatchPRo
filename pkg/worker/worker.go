package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"patchpro/pkg/models"
	"patchpro/slack"
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

	log.Printf("Cloning repository: %s, Branch: %s", j.Repo.URL, j.Repo.DefaultBranch)
	repo, err := git.PlainClone(workDir, false, &git.CloneOptions{
		URL:           j.Repo.URL,
		ReferenceName: plumbing.NewBranchReferenceName(j.Repo.DefaultBranch),
		Depth:         1,
		Auth:          auth(j.Repo.URL),
	})
	if err != nil {
		return fmt.Errorf("git clone: %w", err)
	}

	branch := fmt.Sprintf("patchpro/%s", time.Now().Format("2006-01-02"))
	log.Printf("Checking out new branch: %s", branch)
	wt, _ := repo.Worktree()
	if err := wt.Checkout(&git.CheckoutOptions{Branch: plumbing.NewBranchReferenceName(branch), Create: true}); err != nil {
		return fmt.Errorf("checkout branch: %w", err)
	}

	// Apply patch
	log.Printf("Applying patches for %d modules", len(j.Modules))
	if err := patchRepo(workDir, j.Modules); err != nil {
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
		if err := validate(workDir); err != nil {
			return err
		}
	}

	// Commit & push
	{
		sig := &object.Signature{Name: "cve-bot", Email: "bot@example.com", When: time.Now()}
		log.Printf("Committing changes")
		wt.Add(".")
		message := fmt.Sprintf("chore: fix CVEs\n\nSigned-off-by: %s <%s>", sig.Name, sig.Email)
		_, err := wt.Commit(message, &git.CommitOptions{Author: sig})
		if err != nil {
			return fmt.Errorf("commit failed: %w", err)
		}

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
		prURL, err := createPR(owner, repoName, baseBranch, headBranch, title, bodyStr, j.Repo.UpstreamURL)
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

func getToken(repoURL string) string {
	if strings.Contains(repoURL, "github.ibm.com") {
		return os.Getenv("GITHUB_IBM_TOKEN")
	}
	return os.Getenv("GITHUB_PUBLIC_TOKEN")
}

func auth(repoURL string) *githttp.BasicAuth {
	token := getToken(repoURL)
	return &githttp.BasicAuth{Username: "x-access-token", Password: token}
}

func getBaseURL(repoURL string) string {
	if strings.Contains(repoURL, "github.ibm.com") {
		return "https://github.ibm.com/api/v3"
	}
	return "https://api.github.com"
}

func createPR(repoOwner, repoName, baseBranch, headBranch, title, body, repoURL string) (string, error) {
	baseURL := getBaseURL(repoURL)
	token := getToken(repoURL)
	url := fmt.Sprintf("%s/repos/%s/%s/pulls", baseURL, repoOwner, repoName)

	// Log request details for debugging
	log.Printf("Creating PR for repo: %s/%s, URL: %s, Base: %s, Head: %s", repoOwner, repoName, url, baseBranch, headBranch)

	prData := map[string]interface{}{
		"title": title,
		"body":  body,
		"head":  headBranch,
		"base":  baseBranch,
	}

	jsonData, err := json.Marshal(prData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal PR data: %v", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("PR creation failed (%d): %s", resp.StatusCode, string(bodyBytes))
	}

	var prResponse struct {
		HTMLURL string `json:"html_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&prResponse); err != nil {
		return "", fmt.Errorf("failed to decode PR response: %v", err)
	}

	return prResponse.HTMLURL, nil
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
