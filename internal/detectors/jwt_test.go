package detectors

import "testing"

func TestJWTToken(t *testing.T) {
	data := []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWJjIn0.sgnQY2xpZW50c2lnbg")
	fs := JWTToken("jwt.txt", data)
	if len(fs) == 0 {
		t.Fatalf("expected jwt finding")
	}
}
