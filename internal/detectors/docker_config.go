package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reDockerAuth = regexp.MustCompile(`"auth"\s*:\s*"[A-Za-z0-9+/=]{12,}"`)

func DockerConfigAuth(path string, data []byte) []types.Finding {
	return findSimple(path, data, reDockerAuth, "docker_config_auth", types.SevHigh, 0.9)
}
