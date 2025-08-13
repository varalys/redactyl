package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reNewRelicAPIKey = regexp.MustCompile(`\b(?:NRAK|NRAL|NRII|NRAA)-[A-Z0-9]{27,}\b`)

func NewRelicAPIKey(path string, data []byte) []types.Finding {
	return findSimple(path, data, reNewRelicAPIKey, "newrelic_api_key", types.SevHigh, 0.95)
}
