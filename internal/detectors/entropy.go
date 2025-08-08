package detectors

import (
	"bufio"
	"bytes"
	"math"
	"regexp"

	"github.com/redactyl/redactyl/internal/types"
)

var reMaybeSecret = regexp.MustCompile(`[A-Za-z0-9+/=_-]{20,}`) // broad token-ish
var reContext = regexp.MustCompile(`(?i)(secret|token|password|api[_-]?key|authorization|bearer|aws)`)

func EntropyNearbySecrets(path string, data []byte) []types.Finding {
	var out []types.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		txt := sc.Text()
		if !reContext.MatchString(txt) {
			continue
		}
		for _, m := range reMaybeSecret.FindAllString(txt, -1) {
			if entropy(m) >= 4.0 && len(m) <= 200 {
				out = append(out, types.Finding{
					Path: path, Line: line, Match: m,
					Detector: "entropy_context", Severity: types.SevMed, Confidence: 0.6,
				})
			}
		}
	}
	return out
}

func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	count := map[rune]int{}
	for _, r := range s {
		count[r]++
	}
	H := 0.0
	n := float64(len(s))
	for _, c := range count {
		p := float64(c) / n
		H += -p * math.Log2(p)
	}
	return H
}
