package detectors

import "testing"

func TestPineconeAPIKey(t *testing.T) {
	data := []byte("PINECONE_API_KEY=abcdefghijklmnopqrstuvwxyz012345")
	fs := PineconeAPIKey(".env", data)
	if len(fs) == 0 {
		t.Fatalf("expected pinecone_api_key finding")
	}
}
