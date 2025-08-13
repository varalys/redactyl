package detectors

import "testing"

func TestRenderAPIKey(t *testing.T) {
	if len(RenderAPIKey("x.txt", []byte("rnd_abcdefghijklmnopqrstuvwxyz0123456789ABCD"))) == 0 {
		t.Fatalf("expected finding")
	}
	if len(RenderAPIKey("x.txt", []byte("rnd_short"))) != 0 {
		t.Fatalf("unexpected")
	}
}
