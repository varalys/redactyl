package files

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppendIgnore_IdempotentAndCreates(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".gitignore")
	// Initially missing; call should create and write pattern with newline
	if err := AppendIgnore(dir, "dist/"); err != nil {
		t.Fatalf("AppendIgnore: %v", err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(b) != "dist/\n" {
		t.Fatalf("unexpected content: %q", string(b))
	}
	// Call again: idempotent, no duplicate lines
	if err := AppendIgnore(dir, "dist/"); err != nil {
		t.Fatalf("AppendIgnore second: %v", err)
	}
	b2, _ := os.ReadFile(p)
	if strings.Count(string(b2), "dist/") != 1 {
		t.Fatalf("expected single occurrence, got: %q", string(b2))
	}
}

func TestDefaultGeneratedIgnores(t *testing.T) {
	items := DefaultGeneratedIgnores()
	want1, want2 := "*.pb.go", "*.gen.*"
	found1, found2 := false, false
	for _, it := range items {
		if it == want1 {
			found1 = true
		}
		if it == want2 {
			found2 = true
		}
	}
	if !found1 || !found2 {
		t.Fatalf("expected default ignores to contain %q and %q, got: %#v", want1, want2, items)
	}
}
