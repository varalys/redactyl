package detectors

import (
	"bufio"
	"bytes"
	"regexp"

	"github.com/redactyl/redactyl/internal/types"
	"github.com/redactyl/redactyl/internal/validate"
)

// PAT formats evolve; cover ghp_, gho_, ghu_, ghs_, ghr_
var reGHP = regexp.MustCompile(`g(hp|ho|hu|hs|hr)_[A-Za-z0-9]{36}`)

func GitHubToken(path string, data []byte) []types.Finding {
	var out []types.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		if reGHP.FindStringIndex(sc.Text()) != nil {
			m := reGHP.FindString(sc.Text())
			if validate.LooksLikeGitHubToken(m) {
				out = append(out, types.Finding{Path: path, Line: line, Match: m, Detector: "github_token", Severity: types.SevHigh, Confidence: 0.95})
			}
		}
	}
	return out
}
