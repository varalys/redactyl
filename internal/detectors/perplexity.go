package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var rePerplexity = regexp.MustCompile(`\bpplx-[A-Za-z0-9]{30,}\b`)

func PerplexityAPIKey(path string, data []byte) []types.Finding {
	return findSimple(path, data, rePerplexity, "perplexity_api_key", types.SevHigh, 0.95)
}
