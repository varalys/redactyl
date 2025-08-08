package detectors

import "testing"

func TestGitHubToken(t *testing.T) {
	data := []byte("token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	fs := GitHubToken("x.txt", data)
	if len(fs) == 0 {
		t.Fatalf("expected github token finding")
	}
}
