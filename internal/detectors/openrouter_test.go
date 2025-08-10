package detectors

import "testing"

func TestOpenRouterAPIKey(t *testing.T) {
	data := []byte("sk-or-v1-abcdefghijklmnopqrstuvwxyz")
	fs := OpenRouterAPIKey("x.txt", data)
	if len(fs) == 0 {
		t.Fatalf("expected openrouter_api_key finding")
	}
}
