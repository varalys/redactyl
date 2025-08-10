package detectors

import "testing"

func TestMistralAPIKey(t *testing.T) {
	data := []byte("MISTRAL_API_KEY=sk-abcdefghijklmnopqrstuvwxyz0123")
	fs := MistralAPIKey("x.txt", data)
	if len(fs) == 0 {
		t.Fatalf("expected mistral_api_key finding")
	}
}
