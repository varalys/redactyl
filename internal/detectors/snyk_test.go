package detectors

import "testing"

func TestSnykToken(t *testing.T) {
	data := []byte("snyk_abcdefghijklmnopqrstuvwxyz0123456789")
	if len(SnykToken("x.txt", data)) == 0 {
		t.Fatalf("expected snyk_token finding")
	}
}
