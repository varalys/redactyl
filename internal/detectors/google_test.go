package detectors

import "testing"

func TestGoogleAPIKey(t *testing.T) {
	data := []byte("AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	fs := GoogleAPIKey("x.txt", data)
	if len(fs) == 0 {
		t.Fatalf("expected google api key finding")
	}
}
