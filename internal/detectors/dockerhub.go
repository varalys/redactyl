package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reDockerHubPAT = regexp.MustCompile(`\bdckr_pat_[A-Za-z0-9]{64}\b`)

// Docker Hub personal access token
func DockerHubPAT(path string, data []byte) []types.Finding {
	return findSimple(path, data, reDockerHubPAT, "dockerhub_pat", types.SevHigh, 0.95)
}
