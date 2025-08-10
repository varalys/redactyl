package files

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// AppendIgnore ensures the given pattern is present in .gitignore at repoRoot.
// It creates the file if missing and appends a newline if needed. Idempotent.
func AppendIgnore(repoRoot, pattern string) error {
	path := filepath.Join(repoRoot, ".gitignore")
	// read existing lines if present
	existing := map[string]bool{}
	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			existing[line] = true
		}
		_ = f.Close()
	}
	if existing[pattern] {
		return nil
	}
	// append
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	// ensure file ends with newline; OpenFile+append will just write
	if _, err := f.WriteString(pattern + "\n"); err != nil {
		return err
	}
	return nil
}

// DefaultGeneratedIgnores returns common generated patterns that are safe to ignore.
func DefaultGeneratedIgnores() []string {
	return []string{
		"*.pb.go",
		"*.gen.*",
	}
}
