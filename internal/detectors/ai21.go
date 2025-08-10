package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reAI21Ctx = regexp.MustCompile(`(?i)ai21|AI21_API_KEY`)

func AI21APIKey(path string, data []byte) []types.Finding {
	return findWithContext(path, data, reAI21Ctx, reGenericKey32to64, "ai21_api_key", types.SevHigh, 0.9)
}
