package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/redactyl/redactyl/internal/ignore"
)

func TestCountTargets_InlineIgnoreAndMaxBytes(t *testing.T) {
	dir := t.TempDir()
	// files
	small := filepath.Join(dir, "a.txt")
	big := filepath.Join(dir, "big.bin")
	ignFile := filepath.Join(dir, ".redactylignore")
	if err := os.WriteFile(small, []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}
	// big file over threshold
	bigData := make([]byte, 1024*1024)
	if err := os.WriteFile(big, bigData, 0644); err != nil {
		t.Fatal(err)
	}
	// inline ignore in another file included
	ignored := filepath.Join(dir, "ignored.txt")
	if err := os.WriteFile(ignored, []byte("// redactyl:ignore-file\nsecret"), 0644); err != nil {
		t.Fatal(err)
	}
	// ignore pattern to skip ignored.txt too (double ensure)
	if err := os.WriteFile(ignFile, []byte("ignored.txt\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{Root: dir, MaxBytes: 1 << 20}
	n, err := CountTargets(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// working-tree CountTargets includes a.txt, big.bin and the .redactylignore file itself (not auto-ignored).
	// ignored.txt is excluded by .redactylignore. Expect 3.
	if n != 3 {
		t.Fatalf("expected 3 targets, got %d", n)
	}

	// sanity check: matcher compiles
	if _, err := ignore.Load(filepath.Join(dir, ".redactylignore")); err != nil {
		t.Fatal(err)
	}
}
