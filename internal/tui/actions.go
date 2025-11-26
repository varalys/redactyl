package tui

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	tea "github.com/charmbracelet/bubbletea"
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

// extractVirtualFile extracts a file from an archive to a temp directory
// Returns the path to the extracted file or an error
func extractVirtualFile(virtualPath string) (string, error) {
	archive, internal := parseVirtualPath(virtualPath)
	if internal == "" {
		return "", fmt.Errorf("not a virtual path: %s", virtualPath)
	}

	// Create temp directory for extracted files
	tempDir, err := os.MkdirTemp("", "redactyl-extract-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}

	// Determine the final filename (last part of internal path)
	parts := strings.Split(internal, "::")
	filename := parts[len(parts)-1]

	// Create the output file path
	outputPath := filepath.Join(tempDir, filename)

	// Extract based on archive type
	content, err := extractFromArchive(archive, internal)
	if err != nil {
		_ = os.RemoveAll(tempDir) // Best effort cleanup
		return "", err
	}

	// Write to temp file
	if err := os.WriteFile(outputPath, content, 0600); err != nil {
		_ = os.RemoveAll(tempDir) // Best effort cleanup
		return "", fmt.Errorf("failed to write temp file: %w", err)
	}

	return outputPath, nil
}

// extractFromArchive extracts content from an archive given the internal path
func extractFromArchive(archivePath string, internalPath string) ([]byte, error) {
	lower := strings.ToLower(archivePath)

	switch {
	case strings.HasSuffix(lower, ".zip"):
		return extractFromZip(archivePath, internalPath)
	case strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz"):
		return extractFromTarGz(archivePath, internalPath)
	case strings.HasSuffix(lower, ".tar"):
		return extractFromTar(archivePath, internalPath)
	case strings.HasSuffix(lower, ".gz"):
		return extractFromGz(archivePath)
	default:
		return nil, fmt.Errorf("unsupported archive type: %s", archivePath)
	}
}

func extractFromZip(archivePath string, internalPath string) ([]byte, error) {
	// Handle nested paths: "layer::file.txt" means find "file.txt" after traversing "layer"
	parts := strings.Split(internalPath, "::")
	targetFile := parts[len(parts)-1]

	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open zip: %w", err)
	}
	defer func() { _ = r.Close() }()

	// If there's nesting, we need to find the nested archive first
	if len(parts) > 1 {
		// Find the first nested archive
		nestedArchive := parts[0]
		for _, f := range r.File {
			if f.Name == nestedArchive || strings.HasSuffix(f.Name, "/"+nestedArchive) {
				rc, err := f.Open()
				if err != nil {
					continue
				}
				content, err := io.ReadAll(rc)
				_ = rc.Close()
				if err != nil {
					return nil, err
				}
				// Recursively extract from nested archive
				remainingPath := strings.Join(parts[1:], "::")
				return extractFromNestedArchive(nestedArchive, content, remainingPath)
			}
		}
		return nil, fmt.Errorf("nested archive not found: %s", nestedArchive)
	}

	// Direct file in zip
	for _, f := range r.File {
		if f.Name == targetFile || strings.HasSuffix(f.Name, "/"+targetFile) {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer func() { _ = rc.Close() }()
			return io.ReadAll(rc)
		}
	}

	return nil, fmt.Errorf("file not found in zip: %s", targetFile)
}

func extractFromTar(archivePath string, internalPath string) ([]byte, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open tar: %w", err)
	}
	defer func() { _ = f.Close() }()

	return extractFromTarReader(tar.NewReader(f), internalPath)
}

func extractFromTarGz(archivePath string, internalPath string) ([]byte, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open tgz: %w", err)
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer func() { _ = gz.Close() }()

	return extractFromTarReader(tar.NewReader(gz), internalPath)
}

func extractFromTarReader(tr *tar.Reader, internalPath string) ([]byte, error) {
	parts := strings.Split(internalPath, "::")
	targetFile := parts[len(parts)-1]

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}

		// Handle nested archives (like container layers)
		if len(parts) > 1 {
			nestedArchive := parts[0]
			// Match layer.tar pattern for containers
			if strings.HasSuffix(hdr.Name, "/layer.tar") {
				layerID := filepath.Dir(hdr.Name)
				if i := strings.LastIndex(layerID, "/"); i >= 0 {
					layerID = layerID[i+1:]
				}
				if layerID == nestedArchive {
					content, err := io.ReadAll(tr)
					if err != nil {
						return nil, err
					}
					remainingPath := strings.Join(parts[1:], "::")
					return extractFromNestedArchive("layer.tar", content, remainingPath)
				}
			}
			// Direct nested archive match
			if hdr.Name == nestedArchive || strings.HasSuffix(hdr.Name, "/"+nestedArchive) {
				content, err := io.ReadAll(tr)
				if err != nil {
					return nil, err
				}
				remainingPath := strings.Join(parts[1:], "::")
				return extractFromNestedArchive(nestedArchive, content, remainingPath)
			}
			continue
		}

		// Direct file match
		if hdr.Name == targetFile || strings.HasSuffix(hdr.Name, "/"+targetFile) {
			return io.ReadAll(tr)
		}
	}

	return nil, fmt.Errorf("file not found in tar: %s", targetFile)
}

func extractFromGz(archivePath string) ([]byte, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open gz: %w", err)
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer func() { _ = gz.Close() }()

	return io.ReadAll(gz)
}

func extractFromNestedArchive(archiveName string, content []byte, internalPath string) ([]byte, error) {
	lower := strings.ToLower(archiveName)

	switch {
	case strings.HasSuffix(lower, ".zip"):
		r, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
		if err != nil {
			return nil, err
		}
		parts := strings.Split(internalPath, "::")
		targetFile := parts[len(parts)-1]

		if len(parts) > 1 {
			// More nesting
			nestedArchive := parts[0]
			for _, f := range r.File {
				if f.Name == nestedArchive || strings.HasSuffix(f.Name, "/"+nestedArchive) {
					rc, err := f.Open()
					if err != nil {
						continue
					}
					nestedContent, err := io.ReadAll(rc)
					_ = rc.Close()
					if err != nil {
						return nil, err
					}
					remainingPath := strings.Join(parts[1:], "::")
					return extractFromNestedArchive(nestedArchive, nestedContent, remainingPath)
				}
			}
			return nil, fmt.Errorf("nested archive not found: %s", nestedArchive)
		}

		for _, f := range r.File {
			if f.Name == targetFile || strings.HasSuffix(f.Name, "/"+targetFile) {
				rc, err := f.Open()
				if err != nil {
					return nil, err
				}
				defer func() { _ = rc.Close() }()
				return io.ReadAll(rc)
			}
		}
		return nil, fmt.Errorf("file not found in nested zip: %s", targetFile)

	case strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz"):
		gz, err := gzip.NewReader(bytes.NewReader(content))
		if err != nil {
			return nil, err
		}
		defer func() { _ = gz.Close() }()
		return extractFromTarReader(tar.NewReader(gz), internalPath)

	case strings.HasSuffix(lower, ".tar"), strings.HasSuffix(lower, "layer.tar"):
		return extractFromTarReader(tar.NewReader(bytes.NewReader(content)), internalPath)

	default:
		// If it's the final file (not an archive), just return content
		if internalPath == "" || internalPath == archiveName {
			return content, nil
		}
		return nil, fmt.Errorf("unsupported nested archive type: %s", archiveName)
	}
}

// openVirtualFile extracts a virtual file to temp and opens it in the editor
func (m Model) openVirtualFile(f *types.Finding) tea.Cmd {
	return func() tea.Msg {
		tempPath, err := extractVirtualFile(f.Path)
		if err != nil {
			return statusMsg(fmt.Sprintf("Extract failed: %v", err))
		}

		editor := os.Getenv("EDITOR")
		if editor == "" {
			editor = "vim"
		}

		// Build args based on editor type
		var args []string
		editorBase := editor
		if idx := strings.LastIndex(editor, "/"); idx != -1 {
			editorBase = editor[idx+1:]
		}

		switch editorBase {
		case "code", "code-insiders":
			args = []string{"-g", fmt.Sprintf("%s:%d:%d", tempPath, f.Line, f.Column)}
		case "subl", "sublime", "sublime_text":
			args = []string{fmt.Sprintf("%s:%d:%d", tempPath, f.Line, f.Column)}
		case "atom":
			args = []string{fmt.Sprintf("%s:%d:%d", tempPath, f.Line, f.Column)}
		case "emacs", "emacsclient":
			args = []string{fmt.Sprintf("+%d:%d", f.Line, f.Column), tempPath}
		case "nano":
			args = []string{fmt.Sprintf("+%d,%d", f.Line, f.Column), tempPath}
		case "vi", "vim", "nvim":
			if f.Column > 0 {
				args = []string{fmt.Sprintf("+call cursor(%d,%d)", f.Line, f.Column), tempPath}
			} else {
				args = []string{fmt.Sprintf("+%d", f.Line), tempPath}
			}
		default:
			args = []string{fmt.Sprintf("+%d", f.Line), tempPath}
		}

		c := exec.Command(editor, args...)
		c.Stdin = os.Stdin
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr

		if err := c.Run(); err != nil {
			return statusMsg(fmt.Sprintf("Editor error: %v", err))
		}

		// Clean up temp file after editor closes
		_ = os.RemoveAll(filepath.Dir(tempPath))

		return statusMsg(fmt.Sprintf("Opened extracted file: %s", filepath.Base(tempPath)))
	}
}

func (m Model) openEditor() tea.Cmd {
	f := m.getSelectedFinding()
	if f == nil {
		return nil
	}

	// Check for virtual path (inside archive/container)
	if isVirtualPath(f.Path) {
		// Extract to temp and open
		return m.openVirtualFile(f)
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
	defer func() { _ = file.Close() }()

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
		return func() tea.Msg { return statusMsg(fmt.Sprintf("Error marshaling baseline: %v", err)) }
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
		return func() tea.Msg { return statusMsg(fmt.Sprintf("Error marshaling baseline: %v", err)) }
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
		return func() tea.Msg { return statusMsg(fmt.Sprintf("Error marshaling baseline: %v", err)) }
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
	defer func() { _ = file.Close() }()

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
	return func() tea.Msg {
		return statusMsg(fmt.Sprintf("Exported %d findings to %s", len(displayFindings), absPath))
	}
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
		RuleID    string                `json:"ruleId"`
		Level     string                `json:"level"`
		Message   struct{ Text string } `json:"message"`
		Locations []sarifLocation       `json:"locations"`
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
