package detectors

import "testing"

func TestAzureStorageKey(t *testing.T) {
	data := []byte("AccountName=myacct;AccountKey=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=ABCDEFGHIJKLMNOPQRSTUVWXYZ;EndpointSuffix=core.windows.net")
	fs := AzureStorageKey("x.txt", data)
	if len(fs) == 0 {
		t.Fatalf("expected azure storage key finding")
	}
}
