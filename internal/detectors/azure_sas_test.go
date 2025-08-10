package detectors

import "testing"

func TestAzureSASToken(t *testing.T) {
	data := []byte("https://account.blob.core.windows.net/container/blob.txt?sv=2023-01-01&sig=abcDEF0123456789&sp=rl&se=2025-01-01")
	if len(AzureSASToken("x.txt", data)) == 0 {
		t.Fatalf("expected azure_sas_token finding")
	}
}
