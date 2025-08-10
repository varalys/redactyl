package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCountTargets_Staged_RespectsGlobs(t *testing.T) {
	dir := initRepo(t)
	mustWrite := func(name, content string) {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("keep.go", "package x\n")
	mustWrite("skip.txt", "x\n")
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, string(out))
		}
	}
	run("add", "keep.go")
	run("add", "skip.txt")

	n, err := CountTargets(Config{Root: dir, ScanStaged: true, IncludeGlobs: "**/*.go", MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 staged target, got %d", n)
	}
}

func TestCountTargets_History_RespectsGlobs(t *testing.T) {
	dir := initRepo(t)
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, string(out))
		}
	}
	write("x.go", "package x\n")
	run("add", "x.go")
	run("commit", "-m", "x")
	write("y.txt", "y\n")
	run("add", "y.txt")
	run("commit", "-m", "y")

	n, err := CountTargets(Config{Root: dir, HistoryCommits: 2, IncludeGlobs: "**/*.go", MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 history target, got %d", n)
	}
}

func TestCountTargets_Base_RespectsGlobs(t *testing.T) {
	dir := initRepo(t)
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, string(out))
		}
	}
	write("a.go", "one\n")
	write("b.txt", "one\n")
	run("add", "a.go")
	run("add", "b.txt")
	run("commit", "-m", "base")
	run("branch", "base")
	// change files on current branch
	write("a.go", "one\n+two\n")
	write("b.txt", "change\n")
	run("add", "a.go")
	run("add", "b.txt")
	run("commit", "-m", "change")

	n, err := CountTargets(Config{Root: dir, BaseBranch: "base", IncludeGlobs: "**/*.go", MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 base-diff target, got %d", n)
	}
}
