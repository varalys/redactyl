package cache

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type DB struct {
	// Path relative to repo root -> content hash (sha256 hex)
	Entries map[string]string `json:"entries"`
}

func defaultPath(root string) string {
	// Prefer storing cache under .git to avoid accidental commits
	// Fall back to repo root if .git does not exist
	gitDir := filepath.Join(root, ".git")
	if st, err := os.Stat(gitDir); err == nil && st.IsDir() {
		return filepath.Join(gitDir, "redactylcache.json")
	}
	return filepath.Join(root, ".redactylcache.json")
}

func Load(root string) (DB, error) {
	var db DB
	p := defaultPath(root)
	f, err := os.ReadFile(p)
	if err != nil {
		return DB{Entries: map[string]string{}}, err
	}
	if err := json.Unmarshal(f, &db); err != nil {
		return DB{Entries: map[string]string{}}, err
	}
	if db.Entries == nil {
		db.Entries = map[string]string{}
	}
	return db, nil
}

func Save(root string, db DB) error {
	if db.Entries == nil {
		return errors.New("empty cache")
	}
	p := defaultPath(root)
	b, _ := json.MarshalIndent(db, "", "  ")
	return os.WriteFile(p, b, 0644)
}
