package detectors

import "testing"

func TestVercelToken(t *testing.T) {
	pos := []string{
		"vercel_abcdefghijklmnopqrstuvwxyz012345",
		"vc_abcdEFGHijklMNOPqrst-UVWXYZ_123456",
	}
	for _, s := range pos {
		if len(VercelToken("x.txt", []byte(s))) == 0 {
			t.Fatalf("expected finding for %s", s)
		}
	}
	neg := []string{"vercel_short", "vc_"}
	for _, s := range neg {
		if len(VercelToken("x.txt", []byte(s))) != 0 {
			t.Fatalf("unexpected for %s", s)
		}
	}
}
