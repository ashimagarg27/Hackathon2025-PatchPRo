package slack

import (
	"fmt"
	"os"
	"strings"

	"github.com/slack-go/slack"
)

// ReportItem holds information about a processed repository for the Slack report.
type ReportItem struct {
	RepoURL string
	CVEs    []string
	Status  string
	PRURL   string
}

// reports is a global slice to store report items for Slack notifications.
var reports []ReportItem

// AddReportItem adds a report item to the global reports slice.
func AddReportItem(repoURL string, cves []string, status string, prURL string) {
	reports = append(reports, ReportItem{
		RepoURL: repoURL,
		CVEs:    cves,
		Status:  status,
		PRURL:   prURL,
	})
}

// SendSlackAlert sends a formatted report to the specified Slack channel.
func SendSlackAlert(message string) error {
	token := os.Getenv("SLACK_AUTH_TOKEN")
	if token == "" {
		return fmt.Errorf("SLACK_AUTH_TOKEN not set")
	}

	channelID := os.Getenv("SLACK_CHANNEL_ID")
	if channelID == "" {
		return fmt.Errorf("SLACK_CHANNEL_ID not set")
	}

	client := slack.New(token)

	var report strings.Builder
	if message == "report" {
		if len(reports) == 0 {
			report.WriteString("No repositories processed.")
		} else {
			report.WriteString("### PatchPRo Report\n\n")
			for _, item := range reports {
				report.WriteString(fmt.Sprintf("*Repository*: %s\n", item.RepoURL))
				report.WriteString(fmt.Sprintf("*CVEs Fixed*: %s\n", strings.Join(item.CVEs, ", ")))
				report.WriteString(fmt.Sprintf("*Status*: %s\n", item.Status))
				if item.PRURL != "" {
					report.WriteString(fmt.Sprintf("*PR URL*: %s\n", item.PRURL))
				}
				report.WriteString("\n")
			}
		}
	} else {
		report.WriteString(message)
	}

	_, _, err := client.PostMessage(
		channelID,
		slack.MsgOptionText(report.String(), false),
	)
	if err != nil {
		return fmt.Errorf("failed to send Slack message: %v", err)
	}

	return nil
}
