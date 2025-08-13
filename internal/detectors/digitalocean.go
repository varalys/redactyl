package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reDigitalOceanPAT = regexp.MustCompile(`\bdop_v1_[a-f0-9]{64}\b`)

// DigitalOcean personal access token
func DigitalOceanPAT(path string, data []byte) []types.Finding {
	return findSimple(path, data, reDigitalOceanPAT, "digitalocean_pat", types.SevHigh, 0.95)
}
