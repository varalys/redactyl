package detectors

import "testing"

func TestMapboxToken(t *testing.T) {
	data := []byte("pk.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123")
	if len(MapboxToken("x.txt", data)) == 0 {
		t.Fatalf("expected mapbox_token finding")
	}
}
