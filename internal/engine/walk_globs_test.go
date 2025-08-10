package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/franzer/redactyl/internal/ignore"
)

func TestWalk_WithIncludeExcludeGlobs(t *testing.T) {
	dir := t.TempDir()
	mustWrite := func(name, content string) {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("a.txt", "hello")
	mustWrite("b.go", "package main\n")
	mustWrite("c.md", "doc")

	ign, _ := ignore.Load(filepath.Join(dir, ".redactylignore"))

	// Include only *.go
	cfg := Config{Root: dir, IncludeGlobs: "**/*.go", MaxBytes: 1 << 20}
	var got []string
	err := Walk(nil, cfg, ign, func(path string, _ []byte) { got = append(got, path) })
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "b.go" {
		t.Fatalf("include globs failed, got %v", got)
	}

	// Exclude *.md
	got = nil
	cfg = Config{Root: dir, ExcludeGlobs: "**/*.md", MaxBytes: 1 << 20}
	if err := Walk(nil, cfg, ign, func(path string, _ []byte) { got = append(got, path) }); err != nil {
		t.Fatal(err)
	}
	for _, p := range got {
		if p == "c.md" {
			t.Fatalf("exclude globs failed, saw %s", p)
		}
	}
}
