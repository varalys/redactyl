package detectors

import "testing"

func TestDatabricksPAT(t *testing.T) {
	data := []byte("dapiabcdefghijklmnopqrstuvwxyz0123456789")
	if len(DatabricksPAT("x.txt", data)) == 0 {
		t.Fatalf("expected databricks_pat finding")
	}
}
