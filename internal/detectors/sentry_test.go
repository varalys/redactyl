package detectors

import "testing"

func TestSentryDSN(t *testing.T) {
	data := []byte("https://0123456789abcdef0123456789abcdef@o123456.ingest.sentry.io/987654")
	fs := SentryDSN("x.txt", data)
	if len(fs) == 0 {
		t.Fatalf("expected sentry dsn finding")
	}
}
