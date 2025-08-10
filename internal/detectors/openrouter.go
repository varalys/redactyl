package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reOpenRouter = regexp.MustCompile(`\bsk-or-v1-[A-Za-z0-9_-]{20,}\b`)

func OpenRouterAPIKey(path string, data []byte) []types.Finding {
	return findSimple(path, data, reOpenRouter, "openrouter_api_key", types.SevHigh, 0.95)
}
