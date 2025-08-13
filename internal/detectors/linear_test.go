package detectors

import "testing"

func TestLinearAPIKey(t *testing.T) {
	pos := []string{
		"lin_api_abcdefghijklmnopqrstuvwxyz0123456789ABCD",
		"LINEAR=lin_api_abcdefghijklmnopqrstuvwxyz0123456789ABCD",
	}
	for _, s := range pos {
		fs := LinearAPIKey("x.txt", []byte(s))
		if len(fs) == 0 {
			t.Fatalf("expected finding for: %s", s)
		}
	}

	neg := []string{
		"lin_api_short",
		"lin_api_abcdefghijklmnopqrstuvwxyz0123456789ABC", // 39
	}
	for _, s := range neg {
		fs := LinearAPIKey("x.txt", []byte(s))
		if len(fs) != 0 {
			t.Fatalf("unexpected finding for: %s", s)
		}
	}
}
