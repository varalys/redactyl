package detectors

import "testing"

func TestSlackWebhookURL(t *testing.T) {
	data := []byte("https://hooks.slack.com/services/AAAAAAAAB/CCCCCCCCD/abcdefghijklmnopqrstuvwx")
	fs := SlackWebhookURL("x.txt", data)
	if len(fs) == 0 {
		t.Fatalf("expected slack webhook finding")
	}
}
