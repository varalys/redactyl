package detectors

import "testing"

func TestDiscordWebhookURL(t *testing.T) {
	data := []byte("https://discord.com/api/webhooks/123456789012345678/abc_DEF-ghi")
	fs := DiscordWebhookURL("x.txt", data)
	if len(fs) == 0 {
		t.Fatalf("expected discord webhook finding")
	}
}
