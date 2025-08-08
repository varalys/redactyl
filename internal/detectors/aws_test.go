package detectors

import "testing"

func TestAWSKeys(t *testing.T) {
	data := []byte("AKIAABCDEFGHIJKLMNOP\naws_secret_access_key = AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD\n")
	fs := AWSKeys("test.txt", data)
	if len(fs) < 2 {
		t.Fatalf("expected at least 2 findings, got %d", len(fs))
	}
}
