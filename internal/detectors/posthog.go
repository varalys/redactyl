package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var (
	rePostHogProjectKey  = regexp.MustCompile(`\bphc_[A-Za-z0-9]{32}\b`)
	rePostHogPersonalKey = regexp.MustCompile(`\bphx_[A-Za-z0-9]{32}\b`)
)

// PostHog project key
func PostHogProjectKey(path string, data []byte) []types.Finding {
	return findSimple(path, data, rePostHogProjectKey, "posthog_project_key", types.SevHigh, 0.95)
}

// PostHog personal key
func PostHogPersonalKey(path string, data []byte) []types.Finding {
	return findSimple(path, data, rePostHogPersonalKey, "posthog_personal_key", types.SevHigh, 0.95)
}
