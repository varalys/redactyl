package detectors

import (
	"bufio"
	"bytes"
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reSendGrid = regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{32,}\b`)

func SendGridAPIKey(path string, data []byte) []types.Finding {
	var out []types.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		if m := reSendGrid.FindString(sc.Text()); m != "" {
			out = append(out, types.Finding{Path: path, Line: line, Match: m, Detector: "sendgrid_api_key", Severity: types.SevHigh, Confidence: 0.9})
		}
	}
	return out
}
