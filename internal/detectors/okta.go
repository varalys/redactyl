package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var (
	reOktaContext = regexp.MustCompile(`(?i)\b(ssws|okta\.com|okta)\b`)
	reOktaToken   = regexp.MustCompile(`\bSSWS\s+[A-Za-z0-9._-]{40,}\b`)
)

func OktaAPIToken(path string, data []byte) []types.Finding {
	// Prefer context gating to reduce false positives
	return findWithContext(path, data, reOktaContext, reOktaToken, "okta_api_token", types.SevHigh, 0.95)
}
