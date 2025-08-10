package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var (
	reCloudflareCtx   = regexp.MustCompile(`(?i)cloudflare|CF_API_TOKEN|CF_API_KEY|CLOUDFLARE_`)
	reCloudflareToken = regexp.MustCompile(`[A-Za-z0-9]{40,}`)
)

func CloudflareTokens(path string, data []byte) []types.Finding {
	return findWithContext(path, data, reCloudflareCtx, reCloudflareToken, "cloudflare_token", types.SevHigh, 0.9)
}
