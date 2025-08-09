package detectors

import "testing"

func TestTerraformCloudToken(t *testing.T) {
	data := []byte("tfe.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	fs := TerraformCloudToken("x.txt", data)
	if len(fs) == 0 {
		t.Fatalf("expected terraform cloud token finding")
	}
}
