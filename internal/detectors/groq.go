package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reGroq = regexp.MustCompile(`\bgsk_[A-Za-z0-9]{30,}\b`)

func GroqAPIKey(path string, data []byte) []types.Finding {
	return findSimple(path, data, reGroq, "groq_api_key", types.SevHigh, 0.95)
}
