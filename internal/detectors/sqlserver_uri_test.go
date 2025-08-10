package detectors

import "testing"

func TestSQLServerURICreds(t *testing.T) {
	data := []byte("sqlserver://user:secret@host:1433")
	if len(SQLServerURICreds("x.txt", data)) == 0 {
		t.Fatalf("expected sqlserver_uri_creds finding")
	}
}
