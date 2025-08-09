package detectors

import (
	"bufio"
	"bytes"
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reNPMToken = regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)

func NPMToken(path string, data []byte) []types.Finding {
	var out []types.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		if m := reNPMToken.FindString(sc.Text()); m != "" {
			out = append(out, types.Finding{Path: path, Line: line, Match: m, Detector: "npm_token", Severity: types.SevHigh, Confidence: 0.9})
		}
	}
	return out
}
