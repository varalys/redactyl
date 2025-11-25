package tui

import (
	"fmt"
	"time"

	"github.com/charmbracelet/bubbletea"
	"github.com/redactyl/redactyl/internal/report"
	"github.com/redactyl/redactyl/internal/types"
)

func Run(findings []types.Finding, rescanFunc func() ([]types.Finding, error)) error {
	m := NewModel(findings, rescanFunc)
	if _, err := tea.NewProgram(m, tea.WithAltScreen()).Run(); err != nil {
		return fmt.Errorf("error running TUI: %w", err)
	}
	return nil
}

// RunWithBaseline starts TUI with findings and baseline (marks baselined findings)
func RunWithBaseline(findings []types.Finding, baseline report.Baseline, rescanFunc func() ([]types.Finding, error)) error {
	m := NewModelWithBaseline(findings, baseline, rescanFunc)
	if _, err := tea.NewProgram(m, tea.WithAltScreen()).Run(); err != nil {
		return fmt.Errorf("error running TUI: %w", err)
	}
	return nil
}

// RunCached starts TUI with cached results (view-only mode)
func RunCached(findings []types.Finding, rescanFunc func() ([]types.Finding, error), timestamp time.Time) error {
	m := NewModel(findings, rescanFunc)
	m.viewingCached = true
	m.cachedTimestamp = timestamp
	m.lastScanTime = timestamp // Use cached timestamp as last scan time
	if _, err := tea.NewProgram(m, tea.WithAltScreen()).Run(); err != nil {
		return fmt.Errorf("error running TUI: %w", err)
	}
	return nil
}

// RunCachedWithBaseline starts TUI with cached results and baseline
func RunCachedWithBaseline(findings []types.Finding, baseline report.Baseline, rescanFunc func() ([]types.Finding, error), timestamp time.Time) error {
	m := NewModelWithBaseline(findings, baseline, rescanFunc)
	m.viewingCached = true
	m.cachedTimestamp = timestamp
	m.lastScanTime = timestamp // Use cached timestamp as last scan time
	if _, err := tea.NewProgram(m, tea.WithAltScreen()).Run(); err != nil {
		return fmt.Errorf("error running TUI: %w", err)
	}
	return nil
}
