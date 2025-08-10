package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reGitCredsURL = regexp.MustCompile(`https?://[^:\s]+:[^@\s]+@[^\s]+`)

func GitCredentialsURLSecret(path string, data []byte) []types.Finding {
	return findSimple(path, data, reGitCredsURL, "git_credentials_url_secret", types.SevHigh, 0.95)
}
