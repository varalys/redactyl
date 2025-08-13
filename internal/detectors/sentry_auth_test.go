package detectors

import "testing"

func TestSentryAuthToken(t *testing.T) {
	if len(SentryAuthToken("x.txt", []byte("sntrys_abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ_1234"))) == 0 {
		t.Fatalf("expected finding")
	}
	if len(SentryAuthToken("x.txt", []byte("sntrys_short"))) != 0 {
		t.Fatalf("unexpected")
	}
}
