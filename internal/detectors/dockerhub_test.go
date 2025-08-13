package detectors

import "testing"

func TestDockerHubPAT(t *testing.T) {
	pos := "dckr_pat_" + repeat("A", 64)
	if len(DockerHubPAT("x.txt", []byte(pos))) == 0 {
		t.Fatalf("expected finding")
	}
	neg := "dckr_pat_short"
	if len(DockerHubPAT("x.txt", []byte(neg))) != 0 {
		t.Fatalf("unexpected")
	}
}
