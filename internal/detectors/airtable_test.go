package detectors

import "testing"

func TestAirtablePAT(t *testing.T) {
	if len(AirtablePAT("x.txt", []byte("pat_abcdefghijklmnOPQRST"))) == 0 {
		t.Fatalf("expected finding")
	}
	if len(AirtablePAT("x.txt", []byte("pat_short"))) != 0 {
		t.Fatalf("unexpected")
	}
}
