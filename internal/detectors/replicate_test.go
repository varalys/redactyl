package detectors

import "testing"

func TestReplicateAPIToken(t *testing.T) {
	data := []byte("r8_abcdefghijklmnopqrstuvwxyz0123456789")
	fs := ReplicateAPIToken("x.txt", data)
	if len(fs) == 0 {
		t.Fatalf("expected replicate_api_token finding")
	}
}
