package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

// Airtable personal access token
var reAirtablePAT = regexp.MustCompile(`\bpat_[A-Za-z0-9]{14,}\b`)

func AirtablePAT(path string, data []byte) []types.Finding {
	return findSimple(path, data, reAirtablePAT, "airtable_pat", types.SevHigh, 0.9)
}
