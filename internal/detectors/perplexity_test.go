package detectors

import "testing"

func TestPerplexityAPIKey(t *testing.T) {
	data := []byte("pplx-abcdefghijklmnopqrstuvwxyz0123456789")
	fs := PerplexityAPIKey("x.txt", data)
	if len(fs) == 0 {
		t.Fatalf("expected perplexity_api_key finding")
	}
}
