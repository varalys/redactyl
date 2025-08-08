package detectors

import (
	"bufio"
	"bytes"
	"regexp"

	"github.com/redactyl/redactyl/internal/types"
)

// PAT formats evolve; this covers classic ghp_ tokens.
var reGHP = regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`)

func GitHubToken(path string, data []byte) []types.Finding {
	var out []types.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		if reGHP.FindStringIndex(sc.Text()) != nil {
			out = append(out, types.Finding{
				Path: path, Line: line, Match: reGHP.FindString(sc.Text()),
				Detector: "github_token", Severity: types.SevHigh, Confidence: 0.9,
			})
		}
	}
	return out
}
