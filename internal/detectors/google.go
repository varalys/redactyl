package detectors

import (
	"bufio"
	"bytes"
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

// Google API keys are typically AIza + 35 chars; raise confidence
var reGoogleAPIKey = regexp.MustCompile(`\bAIza[0-9A-Za-z-_]{35}\b`)

func GoogleAPIKey(path string, data []byte) []types.Finding {
	var out []types.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		if m := reGoogleAPIKey.FindString(sc.Text()); m != "" {
			out = append(out, types.Finding{Path: path, Line: line, Match: m, Detector: "google_api_key", Severity: types.SevHigh, Confidence: 0.95})
		}
	}
	return out
}
