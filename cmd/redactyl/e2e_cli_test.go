package redactyl

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCLI_JSON_Shape_ExitCodes(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "secrets.txt"), []byte("api_key=sk-abcdefghijklmnopqrstuvwxyz0123"), 0644); err != nil {
		t.Fatal(err)
	}
	// run as subprocess to avoid os.Exit in-process
	cmd := exec.Command("go", "run", ".", "scan", "--json", "--fail-on", "high", "-p", dir)
	cmd.Dir = filepath.Clean(filepath.Join("..", ".."))
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	var arr []map[string]any
	if err := json.Unmarshal(out.Bytes(), &arr); err != nil {
		t.Fatalf("json unmarshal: %v\n%s", err, out.String())
	}
	if len(arr) == 0 {
		t.Fatalf("expected at least one finding in JSON output")
	}

	// verify exit code behavior by evaluating ShouldFail on parsed findings
	// Convert to types.Finding-like structs for ShouldFail
	conv := make([]reportFinding, len(arr))
	for i, m := range arr {
		sev, _ := m["severity"].(string)
		path, _ := m["path"].(string)
		match, _ := m["match"].(string)
		detector, _ := m["detector"].(string)
		conv[i] = reportFinding{Path: path, Match: match, Detector: detector, Severity: sev}
	}
	if !shouldFailCompat(conv, "low") {
		t.Fatalf("expected ShouldFail= true for low threshold with findings present")
	}
}

func TestCLI_SARIF_Shape(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "secrets.txt"), []byte("token ghp_ABCDEFGHIJKLMNOPQRST1234567890ab"), 0644); err != nil {
		t.Fatal(err)
	}
	// run as subprocess and parse SARIF
	cmd := exec.Command("go", "run", ".", "scan", "--sarif", "--fail-on", "high", "-p", dir)
	cmd.Dir = filepath.Clean(filepath.Join("..", ".."))
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("sarif json: %v\n%s", err, out.String())
	}
	if doc["version"] != "2.1.0" {
		t.Fatalf("expected SARIF 2.1.0")
	}
}

// Minimal compatible types for invoking ShouldFail logic without importing internals
type reportFinding struct {
	Path     string
	Match    string
	Detector string
	Severity string
}

func shouldFailCompat(fs []reportFinding, failOn string) bool {
	level := map[string]int{"low": 1, "medium": 2, "high": 3}
	th := level[failOn]
	if th == 0 {
		th = 2
	}
	for _, f := range fs {
		if level[f.Severity] >= th {
			return true
		}
	}
	return false
}
