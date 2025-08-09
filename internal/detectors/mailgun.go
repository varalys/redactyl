package detectors

import (
	"bufio"
	"bytes"
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reMailgunKey = regexp.MustCompile(`\bkey-[0-9a-f]{32}\b`)

func MailgunAPIKey(path string, data []byte) []types.Finding {
	var out []types.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		if m := reMailgunKey.FindString(sc.Text()); m != "" {
			out = append(out, types.Finding{Path: path, Line: line, Match: m, Detector: "mailgun_api_key", Severity: types.SevHigh, Confidence: 0.95})
		}
	}
	return out
}
