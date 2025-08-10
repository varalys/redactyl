package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reCohereCtx = regexp.MustCompile(`(?i)cohere|COHERE_API_KEY`)

func CohereAPIKey(path string, data []byte) []types.Finding {
	return findWithContext(path, data, reCohereCtx, reGenericKey32to64, "cohere_api_key", types.SevHigh, 0.9)
}
