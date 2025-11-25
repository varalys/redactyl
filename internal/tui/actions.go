package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/charmbracelet/bubbletea"
	"github.com/redactyl/redactyl/internal/report"
	"github.com/redactyl/redactyl/internal/types"
)

func (m Model) openEditor() tea.Cmd {
	f := m.getSelectedFinding()
	if f == nil {
		return nil
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
	if idx >= 0 && idx < len(m.findings) {
		return &m.findings[idx]
	}
	return nil
}

type statusMsg string
