package detectors

import "testing"

func TestNewRelicAPIKey(t *testing.T) {
	if len(NewRelicAPIKey("x.txt", []byte("NRAK-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456"))) == 0 {
		t.Fatalf("expected finding")
	}
	if len(NewRelicAPIKey("x.txt", []byte("NRAK-short"))) != 0 {
		t.Fatalf("unexpected")
	}
}
