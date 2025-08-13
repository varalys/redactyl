package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var (
	reHasuraCtx   = regexp.MustCompile(`(?i)\bHASURA_GRAPHQL_ADMIN_SECRET\b`)
	reHasuraValue = regexp.MustCompile(`[:=]\s*(['"][^'"\s]{16,}['"]|[^'"\s]{16,})`)
)

func HasuraAdminSecret(path string, data []byte) []types.Finding {
	return findWithContext(path, data, reHasuraCtx, reHasuraValue, "hasura_admin_secret", types.SevHigh, 0.9)
}
