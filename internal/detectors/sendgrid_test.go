package detectors

import "testing"

func TestSendGridAPIKey(t *testing.T) {
	data := []byte("SG.abcdefghijklmnop.abcdefghijklmnopqrstuvwxyzABCDEFGH123456")
	fs := SendGridAPIKey("x.txt", data)
	if len(fs) == 0 {
		t.Fatalf("expected sendgrid api key finding")
	}
}
