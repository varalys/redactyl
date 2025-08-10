package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reRubyGemsYml = regexp.MustCompile(`:rubygems_api_key:\s*\S+`)

func RubyGemsCredentials(path string, data []byte) []types.Finding {
	return findSimple(path, data, reRubyGemsYml, "rubygems_credentials", types.SevHigh, 0.95)
}
