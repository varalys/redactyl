package detectors

import (
	"bufio"
	"bytes"
	"regexp"

	"github.com/franzer/redactyl/internal/types"
)

var reGitLabPAT = regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20}\b`)

func GitLabToken(path string, data []byte) []types.Finding {
	var out []types.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		if m := reGitLabPAT.FindString(sc.Text()); m != "" {
			out = append(out, types.Finding{Path: path, Line: line, Match: m, Detector: "gitlab_token", Severity: types.SevHigh, Confidence: 0.9})
		}
	}
	return out
}
