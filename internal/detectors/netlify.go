package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reNetlifyToken = regexp.MustCompile(`\bnf_[A-Za-z0-9]{20,}\b`)

func NetlifyToken(path string, data []byte) []types.Finding {
	return findSimple(path, data, reNetlifyToken, "netlify_token", types.SevHigh, 0.9)
}
