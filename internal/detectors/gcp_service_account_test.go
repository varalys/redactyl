package detectors

import "testing"

func TestGCPServiceAccountKey(t *testing.T) {
	data := []byte(`{
        "type": "service_account",
        "private_key": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n"
    }`)
	fs := GCPServiceAccountKey("key.json", data)
	if len(fs) == 0 {
		t.Fatalf("expected gcp service account key finding")
	}
}
