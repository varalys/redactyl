package core

import (
	"testing"
)

func TestScan_Smoke(t *testing.T) {
	cfg := Config{
		Root: t.TempDir(),
		// keep defaults: detectors enabled
	}
	findings, err := Scan(cfg)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	_ = findings // may be empty or nil; success path validated by no error
	ids := DetectorIDs()
	if len(ids) == 0 {
		t.Fatal("expected non-empty detector IDs")
	}
}
