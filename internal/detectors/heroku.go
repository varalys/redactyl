package detectors

import (
	"bufio"
	"bytes"
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

// Heroku API key captured with nearby 'heroku' context
var reHerokuKey = regexp.MustCompile(`(?i)heroku(?:[_\s-]*api[_\s-]*key)?[\s:=\"]+([A-Za-z0-9_-]{32,})`)

func HerokuAPIKey(path string, data []byte) []types.Finding {
	var out []types.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		if m := reHerokuKey.FindStringSubmatch(sc.Text()); len(m) == 2 {
			out = append(out, types.Finding{Path: path, Line: line, Match: m[1], Detector: "heroku_api_key", Severity: types.SevHigh, Confidence: 0.85})
		}
	}
	return out
}
