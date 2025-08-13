package detectors

import "testing"

func TestFlyIOToken(t *testing.T) {
	if len(FlyIOAccessToken("x.txt", []byte("flyv1_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-12345"))) == 0 {
		t.Fatalf("expected finding")
	}
	if len(FlyIOAccessToken("x.txt", []byte("flyv1_short"))) != 0 {
		t.Fatalf("unexpected")
	}
}
