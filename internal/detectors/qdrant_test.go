package detectors

import "testing"

func TestQdrantAPIKey(t *testing.T) {
	data := []byte("QDRANT_API_KEY=abcdefghijklmnopqrstuvwxyz012345")
	fs := QdrantAPIKey(".env", data)
	if len(fs) == 0 {
		t.Fatalf("expected qdrant_api_key finding")
	}
}
