package detectors

import "testing"

func TestGroqAPIKey(t *testing.T) {
	data := []byte("gsk_abcdefghijklmnopqrstuvwxyz0123456789")
	fs := GroqAPIKey("x.txt", data)
	if len(fs) == 0 {
		t.Fatalf("expected groq_api_key finding")
	}
}
