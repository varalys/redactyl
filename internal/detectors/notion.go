package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

// Notion secrets are often 50+ chars; accept 40+
var reNotion = regexp.MustCompile(`\bsecret_[A-Za-z0-9]{40,}\b`)

func NotionAPIKey(path string, data []byte) []types.Finding {
	return findSimple(path, data, reNotion, "notion_api_key", types.SevHigh, 0.95)
}
