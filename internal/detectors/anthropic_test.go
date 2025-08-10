package detectors

import "testing"

func TestAnthropicAPIKey(t *testing.T) {
	data := []byte("sk-ant-abcdefghijklmnopqrstuvwxyz0123456789AB")
	fs := AnthropicAPIKey("x.txt", data)
	if len(fs) == 0 {
		t.Fatalf("expected anthropic_api_key finding")
	}
}
