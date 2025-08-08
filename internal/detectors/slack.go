package detectors

import (
	"bufio"
	"bytes"
	"regexp"

	"github.com/redactyl/redactyl/internal/types"
)

var reSlack = regexp.MustCompile(`(xox[abprs]-[A-Za-z0-9-]{10,48})`)

func SlackToken(path string, data []byte) []types.Finding {
	var out []types.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		if reSlack.FindStringIndex(sc.Text()) != nil {
			out = append(out, types.Finding{
				Path: path, Line: line, Match: reSlack.FindString(sc.Text()),
				Detector: "slack_token", Severity: types.SevHigh, Confidence: 0.85,
			})
		}
	}
	return out
}
