package detectors

import "testing"

func TestNetlifyToken(t *testing.T) {
	if len(NetlifyToken("x.txt", []byte("nf_ABCDEFGHIJKLMNOPQRST"))) == 0 {
		t.Fatalf("expected finding")
	}
	if len(NetlifyToken("x.txt", []byte("nf_short"))) != 0 {
		t.Fatalf("unexpected")
	}
}
