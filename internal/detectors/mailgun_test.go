package detectors

import "testing"

func TestMailgunAPIKey(t *testing.T) {
	data := []byte("MAILGUN_API_KEY=key-0123456789abcdef0123456789abcdef")
	fs := MailgunAPIKey("x.txt", data)
	if len(fs) == 0 {
		t.Fatalf("expected mailgun api key finding")
	}
}
