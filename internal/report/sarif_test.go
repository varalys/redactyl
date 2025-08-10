package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/franzer/redactyl/internal/types"
)

func TestWriteSARIF_Golden(t *testing.T) {
	fs := []types.Finding{
		{Path: "a.go", Line: 10, Match: "ghp_x", Detector: "github_token", Severity: types.SevHigh},
		{Path: "b.txt", Line: 5, Match: "jwt_x", Detector: "jwt", Severity: types.SevMed},
	}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, fs); err != nil {
		t.Fatal(err)
	}
	// validate minimal schema fields present
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["version"] != "2.1.0" {
		t.Fatalf("expected SARIF 2.1.0, got %v", doc["version"])
	}
	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("expected 1 run")
	}
	run := runs[0].(map[string]any)
	tool := run["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)
	// rules should exist under tool.driver.rules and be >= unique detectors
	if rules, ok := driver["rules"].([]any); !ok || len(rules) < 2 {
		t.Fatalf("expected rules with at least 2 entries under tool.driver.rules")
	}
	// snippet text should appear in first result
	results := run["results"].([]any)
	if len(results) == 0 {
		t.Fatalf("expected results")
	}
	res := results[0].(map[string]any)
	locs := res["locations"].([]any)
	phys := locs[0].(map[string]any)["physicalLocation"].(map[string]any)
	region := phys["region"].(map[string]any)
	if _, ok := region["snippet"]; !ok {
		t.Fatalf("expected snippet present")
	}
}
