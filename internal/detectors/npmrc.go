package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reNPMRCAuth = regexp.MustCompile(`(^|\s)[^\s]*:_authToken=\S+`)

func NPMRCAuthToken(path string, data []byte) []types.Finding {
	return findSimple(path, data, reNPMRCAuth, "npmrc_auth_token", types.SevHigh, 0.95)
}
