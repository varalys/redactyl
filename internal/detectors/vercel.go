package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

// Vercel tokens have multiple forms; cover common variants
var reVercelToken = regexp.MustCompile(`\b(?:vercel_[A-Za-z0-9]{24,}|vc\w?_[A-Za-z0-9_-]{20,})\b`)

func VercelToken(path string, data []byte) []types.Finding {
	return findSimple(path, data, reVercelToken, "vercel_token", types.SevHigh, 0.9)
}
