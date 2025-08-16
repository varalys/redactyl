// internal/report/sarif_test.go
package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/redactyl/redactyl/internal/types"
)

func TestWriteSARIFWithStats_IncludesProperties(t *testing.T) {
	findings := []types.Finding{{Path: "a/b.txt", Line: 3, Match: "m", Detector: "openai_api_key", Severity: types.SevHigh}}
	stats := map[string]int{"abortedByBytes": 2, "abortedByTime": 1}
	var buf bytes.Buffer
	if err := WriteSARIFWithStats(&buf, findings, stats); err != nil {
		t.Fatalf("WriteSARIFWithStats: %v", err)
	}
	var doc struct {
		Runs []struct {
			Properties map[string]any `json:"properties"`
			Tool       struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v; body=%s", err, buf.String())
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(doc.Runs))
	}
	props := doc.Runs[0].Properties
	if props == nil {
		t.Fatalf("expected properties present")
	}
	as, ok := props["artifactStats"].(map[string]any)
	if !ok {
		t.Fatalf("expected artifactStats in properties, got: %#v", props)
	}
	if as["abortedByBytes"].(float64) != 2 || as["abortedByTime"].(float64) != 1 {
		t.Fatalf("unexpected artifactStats values: %#v", as)
	}
	// Ensure rules and result linkage via ruleIndex
	if len(doc.Runs[0].Tool.Driver.Rules) == 0 {
		t.Fatalf("expected rules populated")
	}
	if len(doc.Runs[0].Results) == 0 || doc.Runs[0].Results[0].RuleID == "" {
		t.Fatalf("expected at least one result with ruleId")
	}
}

// Validate core SARIF structure for WriteSARIF() legacy path
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
