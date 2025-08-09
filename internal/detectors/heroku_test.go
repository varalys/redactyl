package detectors

import "testing"

func TestHerokuAPIKey(t *testing.T) {
	data := []byte("HEROKU_API_KEY=abcdefghijklmnopqrstuvwxyz0123456789")
	fs := HerokuAPIKey("x.txt", data)
	if len(fs) == 0 {
		t.Fatalf("expected heroku api key finding")
	}
}
