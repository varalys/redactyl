package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

// Sentry auth token (Self-hosted or cloud) example prefix sntrys_
var reSentryAuthToken = regexp.MustCompile(`\bsntrys_[A-Za-z0-9_-]{40,}\b`)

func SentryAuthToken(path string, data []byte) []types.Finding {
	return findSimple(path, data, reSentryAuthToken, "sentry_auth_token", types.SevHigh, 0.9)
}
