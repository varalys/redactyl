package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reReplicate = regexp.MustCompile(`\br8_[A-Za-z0-9]{30,}\b`)

func ReplicateAPIToken(path string, data []byte) []types.Finding {
	return findSimple(path, data, reReplicate, "replicate_api_token", types.SevHigh, 0.95)
}
