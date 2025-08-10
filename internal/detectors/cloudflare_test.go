package detectors

import "testing"

func TestCloudflareTokens(t *testing.T) {
	data := []byte("CF_API_TOKEN=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH")
	fs := CloudflareTokens(".env", data)
	if len(fs) == 0 {
		t.Fatalf("expected cloudflare_token finding")
	}
}
