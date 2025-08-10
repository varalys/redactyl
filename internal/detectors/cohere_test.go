package detectors

import "testing"

func TestCohereAPIKey(t *testing.T) {
	data := []byte("COHERE_API_KEY=abcdefghijklmnopqrstuvwxyz0123456789AB")
	fs := CohereAPIKey("x.txt", data)
	if len(fs) == 0 {
		t.Fatalf("expected cohere_api_key finding")
	}
}
