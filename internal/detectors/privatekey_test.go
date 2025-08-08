package detectors

import "testing"

func TestPrivateKeyBlock(t *testing.T) {
	data := []byte("-----BEGIN PRIVATE KEY-----\nMIIB...\n-----END PRIVATE KEY-----\n")
	fs := PrivateKeyBlock("key.pem", data)
	if len(fs) == 0 {
		t.Fatalf("expected private key block finding")
	}
}
