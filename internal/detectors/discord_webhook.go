package detectors

import (
	"bufio"
	"bytes"
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reDiscordWebhook = regexp.MustCompile(`https://discord\.com/api/webhooks/\d+/[A-Za-z0-9_-]+`)

func DiscordWebhookURL(path string, data []byte) []types.Finding {
	var out []types.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		if m := reDiscordWebhook.FindString(sc.Text()); m != "" {
			out = append(out, types.Finding{Path: path, Line: line, Match: m, Detector: "discord_webhook", Severity: types.SevHigh, Confidence: 0.95})
		}
	}
	return out
}
