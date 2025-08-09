package detectors

import "testing"

func TestFirebaseAPIKey(t *testing.T) {
	data := []byte("firebaseConfig: { apiKey: 'AIzaBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' }")
	fs := FirebaseAPIKey("x.txt", data)
	if len(fs) == 0 {
		t.Fatalf("expected firebase api key finding")
	}
}
