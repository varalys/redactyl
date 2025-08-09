package detectors

import "testing"

func TestStripeWebhookSecret(t *testing.T) {
	data := []byte("whsec_abcdefghijklmnopqrstuvwxyz0123456789")
	fs := StripeWebhookSecret("x.txt", data)
	if len(fs) == 0 {
		t.Fatalf("expected stripe webhook secret finding")
	}
}
