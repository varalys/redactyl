package cache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/redactyl/redactyl/internal/types"
)

type ScanResults struct {
	Findings  []types.Finding `json:"findings"`
	Timestamp time.Time       `json:"timestamp"`
	Root      string          `json:"root"`
	Count     int             `json:"count"`
}

func resultsPath(root string) string {
	gitDir := filepath.Join(root, ".git")
	if st, err := os.Stat(gitDir); err == nil && st.IsDir() {
		return filepath.Join(gitDir, "redactyl_last_scan.json")
	}
	return filepath.Join(root, ".redactyl_last_scan.json")
}

func SaveResults(root string, findings []types.Finding) error {
	p := resultsPath(root)
	results := ScanResults{
		Findings:  findings,
		Timestamp: time.Now(),
		Root:      root,
		Count:     len(findings),
	}
	b, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0644)
}

func LoadResults(root string) (ScanResults, error) {
	var results ScanResults
	p := resultsPath(root)
	f, err := os.ReadFile(p)
	if err != nil {
		return results, err
	}
	if err := json.Unmarshal(f, &results); err != nil {
		return results, err
	}
	return results, nil
}
