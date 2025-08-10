package detectors

import "testing"

func TestKaggleJSONKey(t *testing.T) {
	data := []byte("{\n  \"username\": \"user\",\n  \"key\": \"abcdefghijklmnopqrstuvwxyz012345\"\n}")
	fs := KaggleJSONKey("kaggle.json", data)
	if len(fs) == 0 {
		t.Fatalf("expected kaggle_json_key finding")
	}
}
