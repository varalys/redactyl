package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reQdrantCtx = regexp.MustCompile(`(?i)QDRANT_API_KEY|qdrant`)

func QdrantAPIKey(path string, data []byte) []types.Finding {
	return findWithContext(path, data, reQdrantCtx, reGenericKey32to64, "qdrant_api_key", types.SevHigh, 0.9)
}
