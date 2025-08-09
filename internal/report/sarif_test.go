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
}
