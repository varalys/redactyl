package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var (
	reSupabaseSRKCtx   = regexp.MustCompile(`(?i)\bSUPABASE_SERVICE_ROLE_KEY\b`)
	reSupabaseSRKValue = regexp.MustCompile(`[:=]\s*(['"][^'"\s]{16,}['"]|[^'"\s]{16,})`)
)

func SupabaseServiceRoleKey(path string, data []byte) []types.Finding {
	return findWithContext(path, data, reSupabaseSRKCtx, reSupabaseSRKValue, "supabase_service_role_key", types.SevHigh, 0.9)
}
