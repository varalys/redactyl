package detectors

import "testing"

func TestNotionAPIKey(t *testing.T) {
	data := []byte("secret_abcdefghijklmnopqrstuvwxyz0123456789ABCDE")
	if len(NotionAPIKey("x.txt", data)) == 0 {
		t.Fatalf("expected notion_api_key finding")
	}
}
