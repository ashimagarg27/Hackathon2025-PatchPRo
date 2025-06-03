package main

import (
	"log"
	"os"

	"github.com/slack-go/slack"
)

func initSlackClient() *slack.Client {
	token := os.Getenv("SLACK_AUTH_TOKEN")
	if token == "" {
		log.Fatal("slack auth token not set")
	}
	return slack.New(token, slack.OptionDebug(true))
}

func SendSlackAlert(message string) {
	client := initSlackClient()
	channelID := os.Getenv("SLACK_CHANNEL_ID")
	if channelID == "" {
		log.Fatal("slack channal ID not set")
	}

	_, _, err := client.PostMessage(channelID, slack.MsgOptionText(message, false))
	if err != nil {
		log.Printf("Slack send error: %v", err)
	}
}
