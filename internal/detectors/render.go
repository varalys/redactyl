package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reRenderAPIKey = regexp.MustCompile(`\brnd_[A-Za-z0-9]{32,}\b`)

func RenderAPIKey(path string, data []byte) []types.Finding {
	return findSimple(path, data, reRenderAPIKey, "render_api_key", types.SevHigh, 0.95)
}
