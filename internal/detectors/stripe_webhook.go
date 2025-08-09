package detectors

import (
	"bufio"
	"bytes"
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reStripeWebhook = regexp.MustCompile(`\bwhsec_[A-Za-z0-9]{16,}\b`)

func StripeWebhookSecret(path string, data []byte) []types.Finding {
	var out []types.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		if m := reStripeWebhook.FindString(sc.Text()); m != "" {
			out = append(out, types.Finding{Path: path, Line: line, Match: m, Detector: "stripe_webhook_secret", Severity: types.SevHigh, Confidence: 0.9})
		}
	}
	return out
}
