package engine

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/redactyl/redactyl/internal/git"
	"github.com/redactyl/redactyl/internal/ignore"
)

// Walk traverses the working tree and invokes handle for each eligible file.
func Walk(ctx context.Context, cfg Config, ign ignore.Matcher, handle func(path string, data []byte)) error {
	return filepath.WalkDir(cfg.Root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			// Default exclude directories
			if cfg.DefaultExcludes && (strings.HasPrefix(name, ".git") || name == "node_modules" || name == "target" || name == "vendor" ||
				name == "dist" || name == "build" || name == "out" || name == ".venv" || name == "venv" ||
				name == "__pycache__" || name == "coverage" || name == "bin" || name == "obj") {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(cfg.Root, p)
		if ign.Match(rel) {
			return nil
		}
		info, _ := d.Info()
		if info != nil && info.Size() > cfg.MaxBytes {
			return nil
		}
		// Cheap extension-based skips
		lower := strings.ToLower(rel)
		switch {
		case strings.HasSuffix(lower, ".min.js"), strings.HasSuffix(lower, ".map"),
			strings.HasSuffix(lower, ".png"), strings.HasSuffix(lower, ".jpg"), strings.HasSuffix(lower, ".jpeg"), strings.HasSuffix(lower, ".gif"), strings.HasSuffix(lower, ".webp"), strings.HasSuffix(lower, ".svg"),
			strings.HasSuffix(lower, ".pdf"), strings.HasSuffix(lower, ".zip"), strings.HasSuffix(lower, ".gz"), strings.HasSuffix(lower, ".tar"), strings.HasSuffix(lower, ".tgz"), strings.HasSuffix(lower, ".7z"),
			strings.HasSuffix(lower, ".jar"), strings.HasSuffix(lower, ".class"), strings.HasSuffix(lower, ".exe"), strings.HasSuffix(lower, ".dll"), strings.HasSuffix(lower, ".so"):
			if cfg.DefaultExcludes {
				return nil
			}
		}
		// crude binary skip
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		// Inline ignore directive
		if strings.Contains(string(b), "redactyl:ignore-file") {
			return nil
		}
		if looksBinary(b) {
			return nil
		}
		handle(rel, b)
		return nil
	})
}

func looksBinary(b []byte) bool {
	const sniff = 800
	n := sniff
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if b[i] == 0 {
			return true
		}
	}
	return false
}

// CountTargets estimates the number of files to process based on cfg.
// It mirrors selection logic used by Scan paths but avoids heavy reads.
func CountTargets(cfg Config) (int, error) {
	ign, _ := ignore.Load(filepath.Join(cfg.Root, ".redactylignore"))
	// history
	if cfg.HistoryCommits > 0 {
		entries, err := git.LastNCommits(cfg.Root, cfg.HistoryCommits)
		if err != nil {
			return 0, nil
		}
		n := 0
		for _, e := range entries {
			for path, blob := range e.Files {
				if ign.Match(path) {
					continue
				}
				if int64(len(blob)) > cfg.MaxBytes {
					continue
				}
				n++
			}
		}
		return n, nil
	}
	// base branch diff
	if cfg.BaseBranch != "" {
		files, data, err := git.DiffAgainst(cfg.Root, cfg.BaseBranch)
		if err != nil {
			return 0, nil
		}
		n := 0
		for i, p := range files {
			if ign.Match(p) {
				continue
			}
			if int64(len(data[i])) > cfg.MaxBytes {
				continue
			}
			n++
		}
		return n, nil
	}
	// staged
	if cfg.ScanStaged {
		files, data, err := git.StagedDiff(cfg.Root)
		if err != nil {
			return 0, nil
		}
		n := 0
		for i, p := range files {
			if ign.Match(p) {
				continue
			}
			if int64(len(data[i])) > cfg.MaxBytes {
				continue
			}
			n++
		}
		return n, nil
	}
	// working tree
	count := 0
	_ = filepath.WalkDir(cfg.Root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if strings.HasPrefix(name, ".git") || name == "node_modules" || name == "target" || name == "vendor" ||
				name == "dist" || name == "build" || name == "out" || name == ".venv" || name == "venv" ||
				name == "__pycache__" || name == "coverage" || name == "bin" || name == "obj" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(cfg.Root, p)
		if ign.Match(rel) {
			return nil
		}
		info, _ := d.Info()
		if info != nil && info.Size() > cfg.MaxBytes {
			return nil
		}
		lower := strings.ToLower(rel)
		switch {
		case strings.HasSuffix(lower, ".min.js"), strings.HasSuffix(lower, ".map"),
			strings.HasSuffix(lower, ".png"), strings.HasSuffix(lower, ".jpg"), strings.HasSuffix(lower, ".jpeg"), strings.HasSuffix(lower, ".gif"), strings.HasSuffix(lower, ".webp"), strings.HasSuffix(lower, ".svg"),
			strings.HasSuffix(lower, ".pdf"), strings.HasSuffix(lower, ".zip"), strings.HasSuffix(lower, ".gz"), strings.HasSuffix(lower, ".tar"), strings.HasSuffix(lower, ".tgz"), strings.HasSuffix(lower, ".7z"),
			strings.HasSuffix(lower, ".jar"), strings.HasSuffix(lower, ".class"), strings.HasSuffix(lower, ".exe"), strings.HasSuffix(lower, ".dll"), strings.HasSuffix(lower, ".so"):
			return nil
		}
		count++
		return nil
	})
	return count, nil
}
