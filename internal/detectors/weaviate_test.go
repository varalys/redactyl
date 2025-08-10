package detectors

import "testing"

func TestWeaviateAPIKey(t *testing.T) {
	data := []byte("WEAVIATE_API_KEY=abcdefghijklmnopqrstuvwxyz012345")
	fs := WeaviateAPIKey(".env", data)
	if len(fs) == 0 {
		t.Fatalf("expected weaviate_api_key finding")
	}
}
