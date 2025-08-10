package detectors

import "testing"

func TestPyPIToken(t *testing.T) {
	data := []byte("pypi-abcdefghijklmnopqrstuvwxyz_ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789abcdef")
	if len(PyPIToken("x.txt", data)) == 0 {
		t.Fatalf("expected pypi_token finding")
	}
}
