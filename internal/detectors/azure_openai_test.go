package detectors

import "testing"

func TestAzureOpenAIAPIKey(t *testing.T) {
	data := []byte("AZURE_OPENAI_API_KEY=abcdefghijklmnopqrstuvwxyz0123456789AB")
	fs := AzureOpenAIAPIKey("x.txt", data)
	if len(fs) == 0 {
		t.Fatalf("expected azure_openai_api_key finding")
	}
}
