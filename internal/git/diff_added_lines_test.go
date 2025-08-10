package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiffAgainst_OnlyAddedLines(t *testing.T) {
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, string(out))
		}
	}
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	run("init", ".")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "tester")

	write("f.txt", "A\nB\nC\n")
	run("add", "f.txt")
	run("commit", "-m", "base")
	run("branch", "base")

	// Modify: remove B, add D
	write("f.txt", "A\nC\nD\n")
	run("add", "f.txt")
	run("commit", "-m", "change")

	files, data, err := DiffAgainst(dir, "base")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 file in diff, got %d", len(files))
	}
	s := string(data[0])
	if strings.Contains(s, "B\n") {
		t.Fatalf("expected removed lines excluded, saw: %q", s)
	}
	if !strings.Contains(s, "D\n") {
		t.Fatalf("expected added line included, payload: %q", s)
	}
}
