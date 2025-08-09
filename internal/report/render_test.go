package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/franzer/redactyl/internal/types"
)

func TestPrintTable_NoFindings_ShowsFooter(t *testing.T) {
	var buf bytes.Buffer
	PrintTable(&buf, nil, PrintOptions{Duration: 1200 * time.Millisecond, FilesScanned: 10})
	out := buf.String()
	if !strings.Contains(out, "No secrets found") {
		t.Fatalf("expected friendly no-findings message; got: %q", out)
	}
	if !strings.Contains(out, "Files scanned: 10") {
		t.Fatalf("expected footer with files scanned; got: %q", out)
	}
}

func TestPrintTable_WithFindings(t *testing.T) {
	var buf bytes.Buffer
	fs := []types.Finding{{Path: "a.go", Line: 1, Match: "ghp_xxx", Detector: "github_token", Severity: types.SevHigh}}
	PrintTable(&buf, fs, PrintOptions{NoColor: true})
	out := buf.String()
	if !strings.Contains(out, "Findings: 1") {
		t.Fatalf("expected findings header; got: %q", out)
	}
	if !strings.Contains(out, "github_token") {
		t.Fatalf("expected detector column; got: %q", out)
	}
}
