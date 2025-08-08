package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run := func(name string, args ...string) {
		cmd := exec.Command(name, args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("cmd %s %v failed: %v\n%s", name, args, err, string(out))
		}
	}
	run("git", "init", ".")
	run("git", "config", "user.email", "test@example.com")
	run("git", "config", "user.name", "tester")
	return dir
}

func TestScan_StagedAndHistoryAndBase(t *testing.T) {
	dir := initRepo(t)
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	git := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, string(out))
		}
	}
	// base commit
	write("a.txt", "hello")
	git("add", "a.txt")
	git("commit", "-m", "add a")
	git("branch", "base")
	// staged change (keep it staged and uncommitted for staged scan)
	write("stage.txt", "AKIAABCDEFGHIJKLMNOP")
	git("add", "stage.txt")
	// staged path
	res, err := ScanWithStats(Config{Root: dir, ScanStaged: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesScanned == 0 {
		t.Fatalf("expected staged files scanned")
	}

	// now add a commit with a secret-like content for history scan
	write("hist.txt", "token=ghp_ABCDEFGHIJKLMNOPQRST1234567890ab")
	git("add", "hist.txt")
	git("commit", "-m", "add hist")

	// history path
	res, err = ScanWithStats(Config{Root: dir, HistoryCommits: 1, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesScanned == 0 {
		t.Fatalf("expected history files scanned")
	}

	// base diff path
	res, err = ScanWithStats(Config{Root: dir, BaseBranch: "base", MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesScanned == 0 {
		t.Fatalf("expected base diff files scanned")
	}
}
