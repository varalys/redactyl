package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reMapboxToken = regexp.MustCompile(`\b(pk\.[A-Za-z0-9]{50,}|sk\.[A-Za-z0-9]{70,})\b`)

func MapboxToken(path string, data []byte) []types.Finding {
	return findSimple(path, data, reMapboxToken, "mapbox_token", types.SevMed, 0.9)
}
