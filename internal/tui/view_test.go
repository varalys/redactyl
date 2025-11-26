package tui

import (
	"testing"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/redactyl/redactyl/internal/types"
)

func TestView_Rendering(t *testing.T) {
	findings := []types.Finding{
		{Path: "file1.go", Detector: "aws-key", Severity: types.SevHigh},
		{Path: "file2.go", Detector: "generic", Severity: types.SevMed},
	}

	m := NewModel(findings, nil)
	m.ready = true
	m.width = 100
	m.height = 40

	// 1. Basic View
	output := m.View()
	if output == "" {
		t.Error("View returned empty string")
	}

	// 2. View with Help
	m.showHelp = true
	output = m.View()
	if output == "" {
		t.Error("View (Help) returned empty string")
	}
	m.showHelp = false

	// 3. View with Export Menu
	m.showExportMenu = true
	output = m.View()
	if output == "" {
		t.Error("View (Export) returned empty string")
	}
	m.showExportMenu = false

	// 4. View with Diff Mode
	m.diffMode = true
	m.diffNewFindings = []types.Finding{{Path: "new.go"}}
	output = m.View()
	if output == "" {
		t.Error("View (Diff) returned empty string")
	}
	m.diffMode = false

	// 5. View Empty
	mEmpty := NewModel(nil, nil)
	mEmpty.ready = true
	mEmpty.width = 100
	mEmpty.height = 40
	output = mEmpty.View()
	if output == "" {
		t.Error("View (Empty) returned empty string")
	}

	// 6. View Scanning
	m.scanning = true
	m.spinner = spinner.New() // Ensure spinner is init
	output = m.View()
	if output == "" {
		t.Error("View (Scanning) returned empty string")
	}
	m.scanning = false
}

func TestInit(t *testing.T) {
	m := NewModel(nil, nil)
	cmd := m.Init()
	if cmd == nil {
		t.Error("Init returned nil command")
	}
}

func TestFormatDuration_Coverage(t *testing.T) {
	// Directly call formatDuration to ensure 100% coverage
	tests := []struct {
		d        time.Duration
		expected string
	}{
		{30 * time.Second, "30s"},
		{5 * time.Minute, "5m"},
		{2 * time.Hour, "2h"},
		{48 * time.Hour, "2d"},
	}

	for _, tt := range tests {
		got := formatDuration(tt.d)
		if got != tt.expected {
			t.Errorf("formatDuration(%v) = %s, want %s", tt.d, got, tt.expected)
		}
	}
}
