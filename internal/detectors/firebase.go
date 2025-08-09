package detectors

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"

	"github.com/franzer/redactyl/internal/types"
)

// Firebase Web API key often same format as Google API key, detect with context
var (
	reFirebaseAPIKey = reGoogleAPIKey
	reFirebaseCtx    = regexp.MustCompile(`(?i)firebase|apiKey|FIREBASE_`)
)

func FirebaseAPIKey(path string, data []byte) []types.Finding {
	var out []types.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		t := sc.Text()
		if strings.Contains(t, "redactyl:ignore") && strings.Contains(t, "firebase") {
			continue
		}
		if reFirebaseCtx.MatchString(t) {
			if m := reFirebaseAPIKey.FindString(t); m != "" {
				out = append(out, types.Finding{Path: path, Line: line, Match: m, Detector: "firebase_api_key", Severity: types.SevMed, Confidence: 0.8})
			}
		}
	}
	return out
}
