package redactyl

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLI_JSON_Shape_ExitCodes(t *testing.T) {
	dir := t.TempDir()
	// Use a pattern that Gitleaks will detect with medium/low severity
	// Pattern with lower entropy (3.5-4.5 range) will map to medium confidence → medium severity
	if err := os.WriteFile(filepath.Join(dir, "secrets.txt"), []byte("token = abc123def456abc123def456abc12"), 0644); err != nil {
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

// New tests for extended JSON and footer counters
func TestCLI_JSONExtended_IncludesStats(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command("go", "run", ".", "scan", "--json", "--json-extended", "-p", dir)
	cmd.Dir = filepath.Clean(filepath.Join("..", ".."))
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("json-extended unmarshal: %v\n%s", err, out.String())
	}
	if sv, ok := doc["schema_version"].(string); !ok || sv == "" {
		t.Fatalf("expected 'schema_version' in extended JSON payload")
	}
	if _, ok := doc["findings"].([]any); !ok {
		t.Fatalf("expected 'findings' array in extended JSON")
	}
	if _, ok := doc["artifact_stats"].(map[string]any); !ok {
		t.Fatalf("expected 'artifact_stats' object in extended JSON")
	}
}

func TestCLI_JSONExtended_StatsNonZeroOnAbort(t *testing.T) {
	// Create a small tar with two entries and force max-entries=1 to trigger abort
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "file.tar")
	{
		f, err := os.Create(tarPath)
		if err != nil {
			t.Fatal(err)
		}
		tw := tar.NewWriter(f)
		_ = tw.WriteHeader(&tar.Header{Name: "a.txt", Mode: 0600, Size: int64(len("hello"))})
		_, _ = tw.Write([]byte("hello"))
		_ = tw.WriteHeader(&tar.Header{Name: "b.txt", Mode: 0600, Size: int64(len("world"))})
		_, _ = tw.Write([]byte("world"))
		_ = tw.Close()
		_ = f.Close()
	}
	cmd := exec.Command("go", "run", ".", "scan", "--json", "--json-extended", "--archives", "--max-entries", "1", "-p", dir)
	cmd.Dir = filepath.Clean(filepath.Join("..", ".."))
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	_ = cmd.Run() // ignore non-zero exit
	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("json unmarshal: %v\n%s", err, out.String())
	}
	stats, ok := doc["artifact_stats"].(map[string]any)
	if !ok {
		t.Fatalf("expected artifact_stats in extended JSON")
	}
	if e, ok := stats["entries"].(float64); !ok || e <= 0 {
		t.Fatalf("expected non-zero entries abort counter; got stats=%#v", stats)
	}
}

func TestCLI_GlobalArtifactBudget_AbortsDeepScan(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "slow.tar")
	{
		f, err := os.Create(tarPath)
		if err != nil {
			t.Fatal(err)
		}
		tw := tar.NewWriter(f)
		for i := 0; i < 2000; i++ {
			name := fmt.Sprintf("f%04d.txt", i)
			_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len("x"))})
			_, _ = tw.Write([]byte("x"))
		}
		_ = tw.Close()
		_ = f.Close()
	}
	cmd := exec.Command("go", "run", ".", "scan", "--json", "--json-extended", "--archives", "--global-artifact-budget", "20ms", "--fail-on", "high", "-p", dir)
	cmd.Dir = filepath.Clean(filepath.Join("..", ".."))
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("json unmarshal: %v\n%s", err, out.String())
	}
	if sv, ok := doc["schema_version"].(string); !ok || sv == "" {
		t.Fatalf("expected schema_version in extended JSON")
	}
	stats, ok := doc["artifact_stats"].(map[string]any)
	if !ok {
		t.Fatalf("expected artifact_stats in extended JSON")
	}
	if v, ok := stats["time"].(float64); !ok || v <= 0 {
		t.Fatalf("expected time counter > 0 in artifact_stats; got %#v", stats)
	}
}

func TestCLI_SARIF_StatsNonZeroOnAbort(t *testing.T) {
	// Same abort scenario, but assert SARIF run.properties.artifactStats
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "file.tar")
	{
		f, err := os.Create(tarPath)
		if err != nil {
			t.Fatal(err)
		}
		tw := tar.NewWriter(f)
		_ = tw.WriteHeader(&tar.Header{Name: "a.txt", Mode: 0600, Size: int64(len("hello"))})
		_, _ = tw.Write([]byte("hello"))
		_ = tw.WriteHeader(&tar.Header{Name: "b.txt", Mode: 0600, Size: int64(len("world"))})
		_, _ = tw.Write([]byte("world"))
		_ = tw.Close()
		_ = f.Close()
	}
	cmd := exec.Command("go", "run", ".", "scan", "--sarif", "--archives", "--max-entries", "1", "-p", dir)
	cmd.Dir = filepath.Clean(filepath.Join("..", ".."))
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
	var sarif map[string]any
	if err := json.Unmarshal(out.Bytes(), &sarif); err != nil {
		t.Fatalf("sarif unmarshal: %v\n%s", err, out.String())
	}
	runs, _ := sarif["runs"].([]any)
	if len(runs) == 0 {
		t.Fatal("expected runs")
	}
	run := runs[0].(map[string]any)
	props, _ := run["properties"].(map[string]any)
	if props == nil {
		t.Fatal("expected run.properties")
	}
	as, _ := props["artifactStats"].(map[string]any)
	if as == nil {
		t.Fatal("expected run.properties.artifactStats")
	}
	if e, ok := as["entries"].(float64); !ok || e <= 0 {
		t.Fatalf("expected non-zero entries abort counter in SARIF; got: %#v", as)
	}
}

func TestCLI_SARIF_GlobalArtifactBudget_TimeCounterPresent(t *testing.T) {
	dir := t.TempDir()
	// Make a tar with many entries to ensure time spent
	tarPath := filepath.Join(dir, "slow.tar")
	{
		f, err := os.Create(tarPath)
		if err != nil {
			t.Fatal(err)
		}
		tw := tar.NewWriter(f)
		for i := 0; i < 2000; i++ {
			name := fmt.Sprintf("f%04d.txt", i)
			_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len("x"))})
			_, _ = tw.Write([]byte("x"))
		}
		_ = tw.Close()
		_ = f.Close()
	}
	cmd := exec.Command("go", "run", ".", "scan", "--sarif", "--archives", "--global-artifact-budget", "20ms", "--fail-on", "high", "-p", dir)
	cmd.Dir = filepath.Clean(filepath.Join("..", ".."))
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
	var sarif map[string]any
	if err := json.Unmarshal(out.Bytes(), &sarif); err != nil {
		t.Fatalf("sarif unmarshal: %v\n%s", err, out.String())
	}
	runs, _ := sarif["runs"].([]any)
	if len(runs) == 0 {
		t.Fatal("expected runs")
	}
	run := runs[0].(map[string]any)
	props, _ := run["properties"].(map[string]any)
	if props == nil {
		t.Fatal("expected run.properties")
	}
	as, _ := props["artifactStats"].(map[string]any)
	if as == nil {
		t.Fatal("expected run.properties.artifactStats")
	}
	if _, ok := as["time"]; !ok {
		t.Fatalf("expected time counter present; got %#v", as)
	}
}

func TestCLI_Artifacts_IncludeExclude_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	makeZip := func(path string, files map[string]string) {
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		zw := zip.NewWriter(f)
		for name, content := range files {
			w, err := zw.Create(name)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = w.Write([]byte(content))
		}
		_ = zw.Close()
		_ = f.Close()
	}
	if err := os.MkdirAll(filepath.Join(dir, "keep"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "drop"), 0755); err != nil {
		t.Fatal(err)
	}
	keepZip := filepath.Join(dir, "keep", "allowed.zip")
	dropZip := filepath.Join(dir, "drop", "blocked.zip")
	// Content that Gitleaks will detect (generic-api-key with high entropy and assignment)
	makeZip(keepZip, map[string]string{"a.txt": "token = ghp_ABCDEFGHIJKLMNOPQRST1234567890ab"})
	makeZip(dropZip, map[string]string{"b.txt": "token = ghp_ABCDEFGHIJKLMNOPQRST1234567890ab"})
	cmd := exec.Command("go", "run", ".", "scan", "--json", "--json-extended", "--archives", "--include", "**/allowed*", "--exclude", "**/blocked*", "--fail-on", "high", "-p", dir)
	cmd.Dir = filepath.Clean(filepath.Join("..", ".."))
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("json unmarshal: %v\n%s", err, out.String())
	}
	arr, _ := doc["findings"].([]any)
	if len(arr) == 0 {
		t.Fatalf("expected findings from allowed.zip; body=%s", out.String())
	}
	foundAllowed := false
	for _, it := range arr {
		m := it.(map[string]any)
		p, _ := m["path"].(string)
		if strings.Contains(p, "allowed.zip::") {
			foundAllowed = true
		}
		if strings.Contains(p, "blocked.zip::") {
			t.Fatalf("should not include findings from blocked.zip: %s", p)
		}
	}
	if !foundAllowed {
		t.Fatalf("expected findings path with allowed.zip:: in it")
	}
}

func TestCLI_Containers_Smoke_JSONExtended(t *testing.T) {
	dir := t.TempDir()
	// Build a fake docker save tar with one layer file that contains a token-like string
	outer := filepath.Join(dir, "image.tar")
	f, err := os.Create(outer)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	man := `[ {"Config":"config.json","Layers":["123/layer.tar"]} ]`
	_ = tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(man))})
	_, _ = tw.Write([]byte(man))
	var layerBuf bytes.Buffer
	ltw := tar.NewWriter(&layerBuf)
	// Use a pattern that Gitleaks will detect (medium entropy → medium severity, won't fail on high)
	content := "api_key = abc123def456abc123def456abc12"
	_ = ltw.WriteHeader(&tar.Header{Name: "etc/app.txt", Mode: 0600, Size: int64(len(content))})
	_, _ = ltw.Write([]byte(content))
	_ = ltw.Close()
	data := layerBuf.Bytes()
	_ = tw.WriteHeader(&tar.Header{Name: "123/layer.tar", Mode: 0600, Size: int64(len(data))})
	_, _ = tw.Write(data)
	_ = tw.Close()
	_ = f.Close()
	cmd := exec.Command("go", "run", ".", "scan", "--json", "--json-extended", "--containers", "--fail-on", "high", "-p", dir)
	cmd.Dir = filepath.Clean(filepath.Join("..", ".."))
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("json unmarshal: %v\n%s", err, out.String())
	}
	arr, _ := doc["findings"].([]any)
	if len(arr) == 0 {
		t.Fatalf("expected at least one finding from container")
	}
	seenLayer := false
	for _, it := range arr {
		m := it.(map[string]any)
		p, _ := m["path"].(string)
		if strings.Contains(p, "image.tar::123/") {
			seenLayer = true
			break
		}
	}
	if !seenLayer {
		t.Fatalf("expected a finding path containing image.tar::123/")
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
