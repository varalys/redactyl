package detectors

import "testing"

func TestDigitalOceanPAT(t *testing.T) {
	pos := "dop_v1_" + repeat("a", 64)
	if len(DigitalOceanPAT("x.txt", []byte(pos))) == 0 {
		t.Fatalf("expected finding")
	}
	neg := "dop_v1_" + repeat("a", 10)
	if len(DigitalOceanPAT("x.txt", []byte(neg))) != 0 {
		t.Fatalf("unexpected")
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
