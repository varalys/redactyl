package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var (
	reZapierWebhook = regexp.MustCompile(`https://hooks\.zapier\.com/hooks/catch/\d+/[A-Za-z0-9]+`)
	reIFTTTWebhook  = regexp.MustCompile(`https://maker\.ifttt\.com/use/[A-Za-z0-9_-]+`)
)

func ZapierWebhookURL(path string, data []byte) []types.Finding {
	return findSimple(path, data, reZapierWebhook, "zapier_webhook_url", types.SevMed, 0.95)
}

func IFTTTWebhookURL(path string, data []byte) []types.Finding {
	return findSimple(path, data, reIFTTTWebhook, "ifttt_webhook_url", types.SevMed, 0.95)
}
