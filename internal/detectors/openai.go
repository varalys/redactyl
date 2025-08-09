package detectors

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"

	"github.com/franzer/redactyl/internal/types"
)

var (
	reOpenAIKey     = regexp.MustCompile(`\bsk-[A-Za-z0-9]{32,}\b`)
	reOpenAIContext = regexp.MustCompile(`(?i)(openai|gpt|chatgpt|openai_api_key|OPENAI_API_KEY)`)
)

func OpenAIAPIKey(path string, data []byte) []types.Finding {
	var out []types.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		t := sc.Text()
		if strings.Contains(t, "redactyl:ignore") && strings.Contains(t, "openai") {
			continue
		}
		if reOpenAIContext.MatchString(t) {
			if m := reOpenAIKey.FindString(t); m != "" {
				out = append(out, types.Finding{Path: path, Line: line, Match: m, Detector: "openai_api_key", Severity: types.SevHigh, Confidence: 0.9})
			}
		}
	}
	return out
}
