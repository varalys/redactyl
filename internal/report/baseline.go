package report

import (
	"encoding/json"
	"os"

	"github.com/franzer/redactyl/internal/types"
)

type Baseline struct {
	Items map[string]bool `json:"items"`
}

func LoadBaseline(path string) (Baseline, error) {
	b := Baseline{Items: map[string]bool{}}
	f, err := os.ReadFile(path)
	if err != nil {
		return b, err
	}
	_ = json.Unmarshal(f, &b)
	return b, nil
}

func SaveBaseline(path string, findings []types.Finding) error {
	b := Baseline{Items: map[string]bool{}}
	for _, f := range findings {
		b.Items[key(f)] = true
	}
	buf, _ := json.MarshalIndent(b, "", "  ")
	return os.WriteFile(path, buf, 0644)
}

func FilterNewFindings(findings []types.Finding, base Baseline) []types.Finding {
	var out []types.Finding
	for _, f := range findings {
		if !base.Items[key(f)] {
			out = append(out, f)
		}
	}
	return out
}

func key(f types.Finding) string {
	return f.Path + "|" + f.Detector + "|" + f.Match
}

func ShouldFail(findings []types.Finding, failOn string) bool {
	level := map[string]int{"low": 1, "medium": 2, "high": 3}
	th := level[failOn]
	if th == 0 {
		th = 2
	}
	for _, f := range findings {
		if level[string(f.Severity)] >= th {
			return true
		}
	}
	return false
}
