package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reFlyIOToken = regexp.MustCompile(`\bflyv1_[A-Za-z0-9_-]{43,}\b`)

func FlyIOAccessToken(path string, data []byte) []types.Finding {
	return findSimple(path, data, reFlyIOToken, "flyio_access_token", types.SevHigh, 0.95)
}
