package tui

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbletea"
	"github.com/redactyl/redactyl/internal/report"
	"github.com/redactyl/redactyl/internal/types"
)

// isVirtualPath checks if a path is a virtual path (inside an archive/container)
func isVirtualPath(path string) bool {
	return strings.Contains(path, "::")
}

// parseVirtualPath extracts archive and internal path from a virtual path
// e.g., "image.tar::layer123::config.yaml" -> ("image.tar", "layer123::config.yaml")
func parseVirtualPath(path string) (archive string, internal string) {
	idx := strings.Index(path, "::")
	if idx == -1 {
		return path, ""
	}
	return path[:idx], path[idx+2:]
}

func (m Model) openEditor() tea.Cmd {
	f := m.getSelectedFinding()
	if f == nil {
		return nil
	}

	// Check for virtual path (inside archive/container)
	if isVirtualPath(f.Path) {
		archive, internal := parseVirtualPath(f.Path)
		return func() tea.Msg {
			return statusMsg(fmt.Sprintf("Cannot open virtual file: %s is inside %s", internal, archive))
		}
	}

	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vim" // Default to vim
	}

	// Build args based on editor type
	var args []string
	editorBase := editor
	// Extract just the editor name (handle paths like /usr/bin/vim)
	if idx := strings.LastIndex(editor, "/"); idx != -1 {
		editorBase = editor[idx+1:]
	}

	switch editorBase {
	case "code", "code-insiders":
		// VS Code: code -g file:line:column
		args = []string{"-g", fmt.Sprintf("%s:%d:%d", f.Path, f.Line, f.Column)}
	case "subl", "sublime", "sublime_text":
		// Sublime: subl file:line:column
		args = []string{fmt.Sprintf("%s:%d:%d", f.Path, f.Line, f.Column)}
	case "atom":
		// Atom: atom file:line:column
		args = []string{fmt.Sprintf("%s:%d:%d", f.Path, f.Line, f.Column)}
	case "emacs", "emacsclient":
		// Emacs: emacs +line:column file
		args = []string{fmt.Sprintf("+%d:%d", f.Line, f.Column), f.Path}
	case "nano":
		// Nano: nano +line,column file
		args = []string{fmt.Sprintf("+%d,%d", f.Line, f.Column), f.Path}
	case "vi", "vim", "nvim":
		// Vim/Neovim: vim +line file (then :column on open)
		// We use +line and normal mode command to jump to column
		if f.Column > 0 {
			args = []string{fmt.Sprintf("+call cursor(%d,%d)", f.Line, f.Column), f.Path}
		} else {
			args = []string{fmt.Sprintf("+%d", f.Line), f.Path}
		}
	default:
		// Generic fallback: try vim-style +line
		args = []string{fmt.Sprintf("+%d", f.Line), f.Path}
	}

	c := exec.Command(editor, args...)
	return tea.ExecProcess(c, func(err error) tea.Msg {
		if err != nil {
			return statusMsg(fmt.Sprintf("Error opening editor: %v", err))
		}
		return statusMsg("Editor closed")
	})
}

func (m Model) ignoreFile() tea.Cmd {
	f := m.getSelectedFinding()
	if f == nil {
		return nil
	}

	// Append to .redactylignore
	file, err := os.OpenFile(".redactylignore", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return func() tea.Msg { return statusMsg(fmt.Sprintf("Error opening .redactylignore: %v", err)) }
	}
	defer file.Close()

	if _, err := file.WriteString(f.Path + "\n"); err != nil {
		return func() tea.Msg { return statusMsg(fmt.Sprintf("Error writing to .redactylignore: %v", err)) }
	}

	return func() tea.Msg { return statusMsg(fmt.Sprintf("Added %s to .redactylignore", f.Path)) }
}

func (m Model) unignoreFile() tea.Cmd {
	f := m.getSelectedFinding()
	if f == nil {
		return nil
	}

	// Read current .redactylignore
	content, err := os.ReadFile(".redactylignore")
	if err != nil {
		return func() tea.Msg { return statusMsg("No .redactylignore file found") }
	}

	// Split into lines and filter out the path
	lines := strings.Split(string(content), "\n")
	var newLines []string
	found := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == f.Path || trimmed == f.Path+"/**" {
			found = true
			continue // Skip this line
		}
		newLines = append(newLines, line)
	}

	if !found {
		return func() tea.Msg { return statusMsg(fmt.Sprintf("%s is not in .redactylignore", f.Path)) }
	}

	// Write back
	newContent := strings.Join(newLines, "\n")
	// Clean up trailing newlines but ensure file ends with one
	newContent = strings.TrimRight(newContent, "\n") + "\n"
	if newContent == "\n" {
		newContent = ""
	}

	if err := os.WriteFile(".redactylignore", []byte(newContent), 0644); err != nil {
		return func() tea.Msg { return statusMsg(fmt.Sprintf("Error writing .redactylignore: %v", err)) }
	}

	return func() tea.Msg { return statusMsg(fmt.Sprintf("Removed %s from .redactylignore", f.Path)) }
}

func (m Model) addToBaseline() tea.Cmd {
	f := m.getSelectedFinding()
	if f == nil {
		return nil
	}

	// Load existing baseline
	base, err := report.LoadBaseline("redactyl.baseline.json")
	if err != nil {
		// If error, maybe it doesn't exist, create new
		base = report.Baseline{Items: map[string]bool{}}
	}

	// Add key
	key := f.Path + "|" + f.Detector + "|" + f.Match
	base.Items[key] = true

	// Save
	// We can't use report.SaveBaseline because it takes []Finding and regenerates.
	// We need to serialize 'base' manually.
	buf, err := json.MarshalIndent(base, "", "  ")
	if err != nil {
		return func() tea.Msg { return statusMsg(fmt.Sprintf("Error marshalling baseline: %v", err)) }
	}

	if err := os.WriteFile("redactyl.baseline.json", buf, 0644); err != nil {
		return func() tea.Msg { return statusMsg(fmt.Sprintf("Error writing baseline: %v", err)) }
	}

	return func() tea.Msg { return statusMsg("Added finding to baseline") }
}

func (m *Model) removeFromBaseline() tea.Cmd {
	f := m.getSelectedFinding()
	if f == nil {
		return nil
	}

	// Check if finding is baselined
	key := f.Path + "|" + f.Detector + "|" + f.Match
	if !m.baselinedSet[key] {
		return func() tea.Msg { return statusMsg("Finding is not baselined") }
	}

	// Load existing baseline
	base, err := report.LoadBaseline("redactyl.baseline.json")
	if err != nil {
		return func() tea.Msg { return statusMsg(fmt.Sprintf("Error loading baseline: %v", err)) }
	}

	// Remove key
	delete(base.Items, key)

	// Save
	buf, err := json.MarshalIndent(base, "", "  ")
	if err != nil {
		return func() tea.Msg { return statusMsg(fmt.Sprintf("Error marshalling baseline: %v", err)) }
	}

	if err := os.WriteFile("redactyl.baseline.json", buf, 0644); err != nil {
		return func() tea.Msg { return statusMsg(fmt.Sprintf("Error writing baseline: %v", err)) }
	}

	// Update local baselinedSet
	delete(m.baselinedSet, key)

	// Rebuild table row for this finding (remove the (b) prefix)
	idx := m.table.Cursor()
	rows := m.table.Rows()
	if idx >= 0 && idx < len(rows) {
		rows[idx][0] = severityText(f.Severity)
		m.table.SetRows(rows)
	}

	return func() tea.Msg { return statusMsg("Removed finding from baseline") }
}

func (m Model) openAuditLog() tea.Cmd {
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vim" // Default to vim
	}

	// Try to find audit log in .git directory first, then repo root
	auditPaths := []string{
		".git/redactyl_audit.jsonl",
		".redactyl_audit.jsonl",
	}

	var auditPath string
	for _, p := range auditPaths {
		if _, err := os.Stat(p); err == nil {
			auditPath = p
			break
		}
	}

	if auditPath == "" {
		return func() tea.Msg {
			return statusMsg("No audit log found - run a scan first")
		}
	}

	c := exec.Command(editor, auditPath)
	return tea.ExecProcess(c, func(err error) tea.Msg {
		if err != nil {
			return statusMsg(fmt.Sprintf("Error opening audit log: %v", err))
		}
		return statusMsg("Audit log viewer closed")
	})
}

func (m Model) getSelectedFinding() *types.Finding {
	idx := m.table.Cursor()

	// Handle grouped mode
	if m.groupMode != GroupNone && len(m.groupedFindings) > 0 {
		if idx >= 0 && idx < len(m.groupedFindings) {
			item := m.groupedFindings[idx]
			if item.IsGroup {
				return nil // Group headers don't have a finding
			}
			return item.Finding
		}
		return nil
	}

	// Normal mode
	displayFindings := m.getDisplayFindings()
	if idx >= 0 && idx < len(displayFindings) {
		// Return pointer to the actual finding (from filtered or all)
		return &displayFindings[idx]
	}
	return nil
}

// getSelectedOriginalIndex returns the index in m.findings for the currently selected item
func (m Model) getSelectedOriginalIndex() int {
	return m.getOriginalIndex(m.table.Cursor())
}

// bulkBaseline adds all selected findings to baseline
func (m *Model) bulkBaseline() tea.Cmd {
	if len(m.selectedFindings) == 0 {
		return func() tea.Msg { return statusMsg("No findings selected") }
	}

	// Load existing baseline
	base, err := report.LoadBaseline("redactyl.baseline.json")
	if err != nil {
		base = report.Baseline{Items: map[string]bool{}}
	}

	// Add all selected findings
	count := 0
	for origIdx := range m.selectedFindings {
		if origIdx >= 0 && origIdx < len(m.findings) {
			f := m.findings[origIdx]
			key := f.Path + "|" + f.Detector + "|" + f.Match
			if !base.Items[key] {
				base.Items[key] = true
				count++
			}
		}
	}

	// Save baseline
	buf, err := json.MarshalIndent(base, "", "  ")
	if err != nil {
		return func() tea.Msg { return statusMsg(fmt.Sprintf("Error marshalling baseline: %v", err)) }
	}

	if err := os.WriteFile("redactyl.baseline.json", buf, 0644); err != nil {
		return func() tea.Msg { return statusMsg(fmt.Sprintf("Error writing baseline: %v", err)) }
	}

	// Clear selection after bulk operation
	m.selectedFindings = make(map[int]bool)

	return func() tea.Msg { return statusMsg(fmt.Sprintf("Added %d findings to baseline", count)) }
}

// bulkIgnore adds all unique files from selected findings to .redactylignore
func (m *Model) bulkIgnore() tea.Cmd {
	if len(m.selectedFindings) == 0 {
		return func() tea.Msg { return statusMsg("No findings selected") }
	}

	// Collect unique file paths
	paths := make(map[string]bool)
	for origIdx := range m.selectedFindings {
		if origIdx >= 0 && origIdx < len(m.findings) {
			paths[m.findings[origIdx].Path] = true
		}
	}

	// Append to .redactylignore
	file, err := os.OpenFile(".redactylignore", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return func() tea.Msg { return statusMsg(fmt.Sprintf("Error opening .redactylignore: %v", err)) }
	}
	defer file.Close()

	for path := range paths {
		if _, err := file.WriteString(path + "\n"); err != nil {
			return func() tea.Msg { return statusMsg(fmt.Sprintf("Error writing to .redactylignore: %v", err)) }
		}
	}

	// Clear selection after bulk operation
	m.selectedFindings = make(map[int]bool)

	return func() tea.Msg { return statusMsg(fmt.Sprintf("Added %d files to .redactylignore", len(paths))) }
}

// copyPathToClipboard copies the current finding's file path to clipboard
func (m Model) copyPathToClipboard() tea.Cmd {
	f := m.getSelectedFinding()
	if f == nil {
		return func() tea.Msg { return statusMsg("No finding selected") }
	}

	if err := clipboard.WriteAll(f.Path); err != nil {
		return func() tea.Msg { return statusMsg(fmt.Sprintf("Clipboard error: %v", err)) }
	}

	return func() tea.Msg { return statusMsg(fmt.Sprintf("Copied: %s", f.Path)) }
}

// copyFindingToClipboard copies full finding details to clipboard
func (m Model) copyFindingToClipboard() tea.Cmd {
	f := m.getSelectedFinding()
	if f == nil {
		return func() tea.Msg { return statusMsg("No finding selected") }
	}

	// Build detailed text representation
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Path: %s\n", f.Path))
	sb.WriteString(fmt.Sprintf("Line: %d\n", f.Line))
	if f.Column > 0 {
		sb.WriteString(fmt.Sprintf("Column: %d\n", f.Column))
	}
	sb.WriteString(fmt.Sprintf("Detector: %s\n", f.Detector))
	sb.WriteString(fmt.Sprintf("Severity: %s\n", f.Severity))
	sb.WriteString(fmt.Sprintf("Match: %s\n", f.Match))
	if f.Secret != "" {
		sb.WriteString(fmt.Sprintf("Secret: %s\n", f.Secret))
	}
	if f.Context != "" {
		sb.WriteString(fmt.Sprintf("\nContext:\n%s\n", f.Context))
	}

	if err := clipboard.WriteAll(sb.String()); err != nil {
		return func() tea.Msg { return statusMsg(fmt.Sprintf("Clipboard error: %v", err)) }
	}

	return func() tea.Msg { return statusMsg("Copied finding details to clipboard") }
}

// exportFindings exports current view to a file
func (m *Model) exportFindings(format string) tea.Cmd {
	displayFindings := m.getDisplayFindings()
	if len(displayFindings) == 0 {
		return func() tea.Msg { return statusMsg("No findings to export") }
	}

	// Generate filename with timestamp
	timestamp := time.Now().Format("20060102-150405")
	var filename string
	var data []byte
	var err error

	switch format {
	case "json":
		filename = fmt.Sprintf("redactyl-export-%s.json", timestamp)
		data, err = json.MarshalIndent(displayFindings, "", "  ")
	case "csv":
		filename = fmt.Sprintf("redactyl-export-%s.csv", timestamp)
		data, err = m.findingsToCSV(displayFindings)
	case "sarif":
		filename = fmt.Sprintf("redactyl-export-%s.sarif", timestamp)
		data, err = m.findingsToSARIF(displayFindings)
	default:
		return func() tea.Msg { return statusMsg(fmt.Sprintf("Unknown format: %s", format)) }
	}

	if err != nil {
		return func() tea.Msg { return statusMsg(fmt.Sprintf("Export error: %v", err)) }
	}

	// Write to current directory
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return func() tea.Msg { return statusMsg(fmt.Sprintf("Write error: %v", err)) }
	}

	absPath, _ := filepath.Abs(filename)
	return func() tea.Msg { return statusMsg(fmt.Sprintf("Exported %d findings to %s", len(displayFindings), absPath)) }
}

// findingsToCSV converts findings to CSV format
func (m *Model) findingsToCSV(findings []types.Finding) ([]byte, error) {
	var sb strings.Builder
	writer := csv.NewWriter(&sb)

	// Header
	if err := writer.Write([]string{"Severity", "Detector", "Path", "Line", "Column", "Match", "Secret"}); err != nil {
		return nil, err
	}

	// Rows
	for _, f := range findings {
		row := []string{
			string(f.Severity),
			f.Detector,
			f.Path,
			fmt.Sprintf("%d", f.Line),
			fmt.Sprintf("%d", f.Column),
			f.Match,
			f.Secret,
		}
		if err := writer.Write(row); err != nil {
			return nil, err
		}
	}

	writer.Flush()
	return []byte(sb.String()), writer.Error()
}

// findingsToSARIF converts findings to SARIF 2.1.0 format
func (m *Model) findingsToSARIF(findings []types.Finding) ([]byte, error) {
	// Simplified SARIF structure
	type sarifLocation struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine   int `json:"startLine"`
				StartColumn int `json:"startColumn,omitempty"`
			} `json:"region"`
		} `json:"physicalLocation"`
	}

	type sarifResult struct {
		RuleID    string          `json:"ruleId"`
		Level     string          `json:"level"`
		Message   struct{ Text string } `json:"message"`
		Locations []sarifLocation `json:"locations"`
	}

	type sarifRun struct {
		Tool struct {
			Driver struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"driver"`
		} `json:"tool"`
		Results []sarifResult `json:"results"`
	}

	type sarifReport struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}

	// Build results
	results := make([]sarifResult, len(findings))
	for i, f := range findings {
		level := "warning"
		switch f.Severity {
		case types.SevHigh:
			level = "error"
		case types.SevLow:
			level = "note"
		}

		loc := sarifLocation{}
		loc.PhysicalLocation.ArtifactLocation.URI = f.Path
		loc.PhysicalLocation.Region.StartLine = f.Line
		if f.Column > 0 {
			loc.PhysicalLocation.Region.StartColumn = f.Column
		}

		results[i] = sarifResult{
			RuleID:    f.Detector,
			Level:     level,
			Message:   struct{ Text string }{Text: fmt.Sprintf("Secret detected: %s", f.Match)},
			Locations: []sarifLocation{loc},
		}
	}

	report := sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: struct {
				Driver struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"driver"`
			}{
				Driver: struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				}{
					Name:    "redactyl",
					Version: "1.0.0",
				},
			},
			Results: results,
		}},
	}

	return json.MarshalIndent(report, "", "  ")
}

type statusMsg string
