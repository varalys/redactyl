package detectors

import "testing"

func TestPostHogKeys(t *testing.T) {
	if len(PostHogProjectKey("x.txt", []byte("phc_abcdefghijklmnopqrstuvwxyz012345"))) == 0 {
		t.Fatalf("expected project key finding")
	}
	if len(PostHogPersonalKey("x.txt", []byte("phx_abcdefghijklmnopqrstuvwxyz012345"))) == 0 {
		t.Fatalf("expected personal key finding")
	}
	if len(PostHogProjectKey("x.txt", []byte("phc_short"))) != 0 {
		t.Fatalf("unexpected")
	}
	if len(PostHogPersonalKey("x.txt", []byte("phx_short"))) != 0 {
		t.Fatalf("unexpected")
	}
}
