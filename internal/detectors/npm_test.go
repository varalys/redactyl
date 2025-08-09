package detectors

import "testing"

func TestNPMToken(t *testing.T) {
	data := []byte("npm_abcdefghijklmnopqrstuvwxyz0123456789")
	fs := NPMToken("x.txt", data)
	if len(fs) == 0 {
		t.Fatalf("expected npm token finding")
	}
}
