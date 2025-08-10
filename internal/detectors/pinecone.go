package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var rePineconeCtx = regexp.MustCompile(`(?i)PINECONE_API_KEY|pinecone`)

func PineconeAPIKey(path string, data []byte) []types.Finding {
	return findWithContext(path, data, rePineconeCtx, reGenericKey32to64, "pinecone_api_key", types.SevHigh, 0.9)
}
