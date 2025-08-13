package detectors

import (
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reNetlifyBuildHook = regexp.MustCompile(`https://api\.netlify\.com/build_hooks/[A-Za-z0-9]{20,}`)

func NetlifyBuildHookURL(path string, data []byte) []types.Finding {
	return findSimple(path, data, reNetlifyBuildHook, "netlify_build_hook", types.SevMed, 0.95)
}
