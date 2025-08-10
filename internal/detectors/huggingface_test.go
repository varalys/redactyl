package detectors

import "testing"

func TestHuggingFaceToken(t *testing.T) {
	data := []byte("hf_abcdefghijklmnopqrstuvwxyz0123456789ABCDE")
	fs := HuggingFaceToken("x.txt", data)
	if len(fs) == 0 {
		t.Fatalf("expected huggingface_token finding")
	}
}
