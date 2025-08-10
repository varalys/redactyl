package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reStabilityCtx = regexp.MustCompile(`(?i)stability|STABILITY_API_KEY`)

func StabilityAPIKey(path string, data []byte) []types.Finding {
	return findWithContext(path, data, reStabilityCtx, reSkKey, "stability_api_key", types.SevHigh, 0.9)
}
