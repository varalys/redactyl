package git

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

func TestLastNCommits(t *testing.T) {
    dir := initRepo(t)
    // create and commit two files
    if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0644); err != nil {
        t.Fatal(err)
    }
    run := func(args ...string) {
        cmd := exec.Command("git", args...)
        cmd.Dir = dir
        if out, err := cmd.CombinedOutput(); err != nil {
            t.Fatalf("git %v: %v\n%s", args, err, string(out))
        }
    }
    run("add", "a.txt")
    run("commit", "-m", "add a")
    if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello world"), 0644); err != nil {
        t.Fatal(err)
    }
    run("add", "a.txt")
    run("commit", "-m", "update a")

    entries, err := LastNCommits(dir, 2)
    if err != nil {
        t.Fatal(err)
    }
    if len(entries) == 0 {
        t.Fatalf("expected some entries")
    }
    found := false
    for _, e := range entries {
        if _, ok := e.Files["a.txt"]; ok {
            found = true
            break
        }
    }
    if !found {
        t.Fatalf("expected a.txt in commit files")
    }
}

func TestStagedDiff(t *testing.T) {
    dir := initRepo(t)
    if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("content"), 0644); err != nil {
        t.Fatal(err)
    }
    run := func(args ...string) {
        cmd := exec.Command("git", args...)
        cmd.Dir = dir
        if out, err := cmd.CombinedOutput(); err != nil {
            t.Fatalf("git %v: %v\n%s", args, err, string(out))
        }
    }
    run("add", "b.txt")
    // don't commit; keep staged
    files, data, err := StagedDiff(dir)
    if err != nil {
        t.Fatal(err)
    }
    if len(files) == 0 || len(data) == 0 {
        t.Fatalf("expected staged diff output")
    }
}

func TestDiffAgainst(t *testing.T) {
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
    write("c.txt", "base")
    run("add", "c.txt")
    run("commit", "-m", "add c")
    run("branch", "base")
    // modify on current branch
    write("c.txt", "base\nchange")
    run("add", "c.txt")
    run("commit", "-m", "change c")

    files, data, err := DiffAgainst(dir, "base")
    if err != nil {
        t.Fatal(err)
    }
    if len(files) == 0 || len(data) == 0 {
        t.Fatalf("expected diff against base")
    }
}


