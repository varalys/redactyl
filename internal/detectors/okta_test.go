package detectors

import "testing"

func TestOktaAPIToken(t *testing.T) {
	pos := "okta.com Authorization: SSWS " + repeat("A", 40)
	if len(OktaAPIToken("x.txt", []byte(pos))) == 0 {
		t.Fatalf("expected finding")
	}
	neg := "SSWS short"
	if len(OktaAPIToken("x.txt", []byte(neg))) != 0 {
		t.Fatalf("unexpected")
	}
}
