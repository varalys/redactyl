package detectors

import "testing"

func TestGitLabToken(t *testing.T) {
	data := []byte("glpat-abcdefghijklmnopqrst")
	fs := GitLabToken("x.txt", data)
	if len(fs) == 0 {
		t.Fatalf("expected gitlab token finding")
	}
}
