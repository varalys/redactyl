package detectors

import "testing"

func TestStabilityAPIKey(t *testing.T) {
	data := []byte("STABILITY_API_KEY=sk-abcdefghijklmnopqrstuvwxyz0123")
	fs := StabilityAPIKey("x.txt", data)
	if len(fs) == 0 {
		t.Fatalf("expected stability_api_key finding")
	}
}
