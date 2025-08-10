package detectors

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"

	"github.com/franzer/redactyl/internal/types"
)

var reKaggleJSONKey = regexp.MustCompile(`"key"\s*:\s*"[A-Za-z0-9_-]{32}"`)

func KaggleJSONKey(path string, data []byte) []types.Finding {
	var out []types.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		t := sc.Text()
		if strings.Contains(t, "redactyl:ignore") && strings.Contains(strings.ToLower(t), "kaggle") {
			continue
		}
		if reKaggleJSONKey.MatchString(t) {
			m := reKaggleJSONKey.FindString(t)
			out = append(out, types.Finding{Path: path, Line: line, Match: m, Detector: "kaggle_json_key", Severity: types.SevHigh, Confidence: 0.95})
		}
	}
	return out
}
