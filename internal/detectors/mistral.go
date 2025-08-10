package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reMistralCtx = regexp.MustCompile(`(?i)mistral|MISTRAL_API_KEY`)

func MistralAPIKey(path string, data []byte) []types.Finding {
	return findWithContext(path, data, reMistralCtx, reSkKey, "mistral_api_key", types.SevHigh, 0.9)
}
