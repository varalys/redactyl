package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reHuggingFace = regexp.MustCompile(`\bhf_[A-Za-z0-9]{35,}\b`)

func HuggingFaceToken(path string, data []byte) []types.Finding {
	return findSimple(path, data, reHuggingFace, "huggingface_token", types.SevHigh, 0.95)
}
