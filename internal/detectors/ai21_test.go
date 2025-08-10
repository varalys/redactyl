package detectors

import "testing"

func TestAI21APIKey(t *testing.T) {
	data := []byte("AI21_API_KEY=abcdefghijklmnopqrstuvwxyz0123456789AB")
	fs := AI21APIKey("x.txt", data)
	if len(fs) == 0 {
		t.Fatalf("expected ai21_api_key finding")
	}
}
