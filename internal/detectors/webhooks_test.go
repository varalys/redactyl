package detectors

import "testing"

func TestZapierWebhookURL(t *testing.T) {
	if len(ZapierWebhookURL("x.txt", []byte("https://hooks.zapier.com/hooks/catch/12345/AbCdE"))) == 0 {
		t.Fatalf("expected finding")
	}
	if len(ZapierWebhookURL("x.txt", []byte("https://hooks.zapier.com/hooks/catch/abc/xyz"))) != 0 {
		t.Fatalf("unexpected")
	}
}

func TestIFTTTWebhookURL(t *testing.T) {
	if len(IFTTTWebhookURL("x.txt", []byte("https://maker.ifttt.com/use/AbCdE_123"))) == 0 {
		t.Fatalf("expected finding")
	}
	if len(IFTTTWebhookURL("x.txt", []byte("https://maker.ifttt.com/notuse/AbCdE_123"))) != 0 {
		t.Fatalf("unexpected")
	}
}
