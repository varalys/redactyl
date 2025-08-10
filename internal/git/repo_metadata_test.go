package git

import (
	"os/exec"
	"testing"
)

func TestRepoMetadata(t *testing.T) {
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, string(out))
		}
	}
	run("init", ".")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "tester")
	run("commit", "--allow-empty", "-m", "init")

	repo, commit, branch := RepoMetadata(dir)
	if commit == "" {
		t.Fatalf("expected non-empty commit")
	}
	if branch == "" {
		t.Fatalf("expected non-empty branch")
	}
	_ = repo // may be empty when no remote configured
}
