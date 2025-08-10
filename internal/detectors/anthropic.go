package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reAnthropic = regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{30,}\b`)

func AnthropicAPIKey(path string, data []byte) []types.Finding {
	return findSimple(path, data, reAnthropic, "anthropic_api_key", types.SevHigh, 0.95)
}
