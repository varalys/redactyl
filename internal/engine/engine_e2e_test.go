package engine

import (
	"os"
	"path/filepath"
	"testing"
)

// Basic end-to-end: create a repo-like dir with a file containing a token,
// run a scan with defaults, and expect at least one finding.
func TestScanWithStats_Basic(t *testing.T) {
	dir := t.TempDir()
	// write a file that will trigger detectors (e.g., GitHub token-like)
	content := "token = ghp_ABCDEFGHIJKLMNOPQRST1234567890ab"
	if err := os.WriteFile(filepath.Join(dir, "config.txt"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	res, err := ScanWithStats(Config{Root: dir, Threads: 2, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatalf("expected findings > 0")
	}
	if res.FilesScanned == 0 {
		t.Fatalf("expected FilesScanned > 0")
	}
}
