package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reSnyk = regexp.MustCompile(`\bsnyk_[A-Za-z0-9]{30,}\b`)

func SnykToken(path string, data []byte) []types.Finding {
	return findSimple(path, data, reSnyk, "snyk_token", types.SevHigh, 0.95)
}
