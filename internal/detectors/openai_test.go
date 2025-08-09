package detectors

import "testing"

func TestOpenAIAPIKey(t *testing.T) {
	data := []byte("OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz012345")
	fs := OpenAIAPIKey("x.txt", data)
	if len(fs) == 0 {
		t.Fatalf("expected openai api key finding")
	}
}
