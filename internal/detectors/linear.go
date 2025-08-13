package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reLinearAPIKey = regexp.MustCompile(`\blin_api_[A-Za-z0-9]{40}\b`)

// Linear API key
func LinearAPIKey(path string, data []byte) []types.Finding {
	return findSimple(path, data, reLinearAPIKey, "linear_api_key", types.SevHigh, 0.95)
}
