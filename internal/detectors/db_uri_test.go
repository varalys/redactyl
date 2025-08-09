package detectors

import "testing"

func TestDBURIs(t *testing.T) {
	data := []byte(`
postgres://user:pass@localhost:5432/dbname
mysql://user:pass@host/db
mongodb://user:pass@cluster/db
`)
	fs := DBURIs("x.txt", data)
	if len(fs) < 3 {
		t.Fatalf("expected at least 3 db uri findings, got %d", len(fs))
	}
}
