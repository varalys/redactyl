package cache

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSave(t *testing.T) {
	dir := t.TempDir()
	// initial load should return empty DB and error
	db, _ := Load(dir)
	if db.Entries == nil {
		t.Fatalf("expected entries map initialized")
	}
	db.Entries["a.txt"] = "deadbeef"
	if err := Save(dir, db); err != nil {
		t.Fatalf("save: %v", err)
	}
	// file should exist
	if _, err := os.Stat(filepath.Join(dir, ".redactylcache.json")); err != nil {
		t.Fatalf("cache file not written: %v", err)
	}
	// load again and verify
	db2, err := Load(dir)
	if err != nil {
		t.Fatalf("load after save: %v", err)
	}
	if got := db2.Entries["a.txt"]; got != "deadbeef" {
		t.Fatalf("unexpected entry: %q", got)
	}
}
