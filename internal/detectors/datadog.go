package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var (
	reDatadogCtx = regexp.MustCompile(`(?i)datadog|DD_API_KEY|DD_APP_KEY`)
	reDDAPIKey   = regexp.MustCompile(`\b[0-9a-fA-F]{32}\b`)
	reDDAppKey   = regexp.MustCompile(`\b[0-9a-fA-F]{40}\b`)
)

func DatadogAPIKey(path string, data []byte) []types.Finding {
	return findWithContext(path, data, reDatadogCtx, reDDAPIKey, "datadog_api_key", types.SevHigh, 0.95)
}

func DatadogAppKey(path string, data []byte) []types.Finding {
	return findWithContext(path, data, reDatadogCtx, reDDAppKey, "datadog_app_key", types.SevHigh, 0.95)
}
