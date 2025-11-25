package tui

import (
	"testing"

	"github.com/redactyl/redactyl/internal/report"
	"github.com/redactyl/redactyl/internal/types"
)

func TestNewModelWithBaseline(t *testing.T) {
	// Create test findings
	findings := []types.Finding{
		{
			Path:     "file1.go",
			Line:     10,
			Column:   5,
			Match:    "secret123",
			Detector: "test-detector",
			Severity: types.SevHigh,
		},
		{
			Path:     "file2.go",
			Line:     20,
			Column:   10,
			Match:    "baselined-secret",
			Detector: "test-detector",
			Severity: types.SevMed,
		},
	}

	// Create baseline with one finding
	baseline := report.Baseline{
		Items: map[string]bool{
			"file2.go|test-detector|baselined-secret": true,
		},
	}

	// Create model with baseline
	rescanFunc := func() ([]types.Finding, error) { return nil, nil }
	m := NewModelWithBaseline(findings, baseline, rescanFunc)

	// Verify baselinedSet was populated
	if m.baselinedSet == nil {
		t.Fatal("baselinedSet should not be nil")
	}

	if len(m.baselinedSet) != 1 {
		t.Errorf("expected 1 baselined item, got %d", len(m.baselinedSet))
	}

	// Verify the first finding is NOT baselined
	if isBaselined(findings[0], m.baselinedSet) {
		t.Error("first finding should not be baselined")
	}

	// Verify the second finding IS baselined
	if !isBaselined(findings[1], m.baselinedSet) {
		t.Error("second finding should be baselined")
	}

	// Verify status message reflects counts
	expectedMsg := "1 new, 1 baselined"
	if len(m.statusMessage) < len(expectedMsg) || m.statusMessage[:len(expectedMsg)] != expectedMsg {
		t.Errorf("expected status to start with '%s', got: %s", expectedMsg, m.statusMessage)
	}
}

func TestNewModelWithBaseline_AllBaselined(t *testing.T) {
	findings := []types.Finding{
		{
			Path:     "file.go",
			Line:     10,
			Column:   5,
			Match:    "secret",
			Detector: "detector",
			Severity: types.SevHigh,
		},
	}

	baseline := report.Baseline{
		Items: map[string]bool{
			"file.go|detector|secret": true,
		},
	}

	rescanFunc := func() ([]types.Finding, error) { return nil, nil }
	m := NewModelWithBaseline(findings, baseline, rescanFunc)

	// When all findings are baselined, status should reflect that
	expectedMsg := "Showing 1 baselined findings"
	if len(m.statusMessage) < len(expectedMsg) || m.statusMessage[:len(expectedMsg)] != expectedMsg {
		t.Errorf("expected status to start with '%s', got: %s", expectedMsg, m.statusMessage)
	}
}

func TestIsBaselined(t *testing.T) {
	baselinedSet := map[string]bool{
		"path/to/file.go|detector-name|secret-match": true,
	}

	tests := []struct {
		name     string
		finding  types.Finding
		expected bool
	}{
		{
			name: "baselined finding",
			finding: types.Finding{
				Path:     "path/to/file.go",
				Detector: "detector-name",
				Match:    "secret-match",
			},
			expected: true,
		},
		{
			name: "not baselined - different path",
			finding: types.Finding{
				Path:     "different/file.go",
				Detector: "detector-name",
				Match:    "secret-match",
			},
			expected: false,
		},
		{
			name: "not baselined - different detector",
			finding: types.Finding{
				Path:     "path/to/file.go",
				Detector: "different-detector",
				Match:    "secret-match",
			},
			expected: false,
		},
		{
			name: "not baselined - different match",
			finding: types.Finding{
				Path:     "path/to/file.go",
				Detector: "detector-name",
				Match:    "different-match",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isBaselined(tt.finding, baselinedSet)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIsBaselined_NilSet(t *testing.T) {
	finding := types.Finding{
		Path:     "file.go",
		Detector: "detector",
		Match:    "match",
	}

	// Should return false for nil set
	if isBaselined(finding, nil) {
		t.Error("should return false for nil baselinedSet")
	}
}
