package tui

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/formatters"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/alecthomas/chroma/v2/styles"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/redactyl/redactyl/internal/audit"
	"github.com/redactyl/redactyl/internal/report"
	"github.com/redactyl/redactyl/internal/types"
)

// Define all Lipgloss styles here.
var (
	// Border styles for main components
	tableBorderStyle = lipgloss.NewStyle().
				BorderStyle(lipgloss.NormalBorder()).
				BorderForeground(lipgloss.Color("240"))

	detailPaneBorderStyle = lipgloss.NewStyle().
				BorderStyle(lipgloss.NormalBorder()).
				BorderForeground(lipgloss.Color("240"))

	// Text styles
	titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("6")). // Cyan
			Bold(true).
			Padding(0, 1)

	matchStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("9")). // Red
			Bold(true)

	keyStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("7")). // White/Light Gray
			Bold(true)

	// Status bar style
	statusStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("236")). // Dark Gray
			Foreground(lipgloss.Color("7"))    // White/Light Gray

	// Empty state message style
	emptyTextStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("15")). // Changed to white for better contrast
			Align(lipgloss.Center)

	// Popup box style for empty state
	popupStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("12")). // Changed to bright cyan for better visibility
			Background(lipgloss.Color("235")).      // Darker background
			Padding(1, 4)                           // Increased horizontal padding slightly, keeps vertical 1.
)

// Severity-specific styles
var (
	sevHighStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))  // Red
	sevMedStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("11")) // Yellow
	sevLowStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("10")) // Green
)

// severityText returns plain text for severity label (no ANSI codes).
// ANSI codes in table cells cause rendering issues when truncated.
func severityText(s types.Severity) string {
	switch s {
	case types.SevHigh:
		return "HIGH"
	case types.SevMed:
		return "MED"
	case types.SevLow:
		return "LOW"
	default:
		return string(s)
	}
}

// isBaselined checks if a finding is in the baseline
func isBaselined(f types.Finding, baselinedSet map[string]bool) bool {
	if baselinedSet == nil {
		return false
	}
	key := f.Path + "|" + f.Detector + "|" + f.Match
	return baselinedSet[key]
}

// formatDuration formats a duration into human-readable string
func formatDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// Model represents the main state of the TUI application.
type Model struct {
	table             table.Model
	viewport          viewport.Model
	spinner           spinner.Model
	findings          []types.Finding
	filteredFindings  []types.Finding // Findings after filter applied (nil = no filter)
	filteredIndices   []int           // Maps filtered index to original findings index
	baselinedSet      map[string]bool // Keys of baselined findings
	quitting          bool
	ready             bool               // Indicates if terminal dimensions are known
	scanning          bool               // True when rescan is in progress
	hasScannedOnce    bool               // True after first scan completes
	initialScanDone   bool               // True if we started with findings (not first ever scan)
	viewingCached     bool               // True when viewing cached results
	cachedTimestamp   time.Time          // Timestamp of cached results
	lastScanTime      time.Time          // Timestamp of the last scan (always set)
	viewingHistorical bool               // True when viewing a historical scan from audit log
	showScanHistory   bool               // True when scan history popup is shown
	scanHistory       []audit.ScanRecord // Loaded scan history
	historySelection  int                // Selected scan in history list (0-based)
	height            int
	width             int
	statusMessage     string
	statusTimeout     *time.Time                      // When to clear status message
	rescanFunc        func() ([]types.Finding, error) // Callback to re-run scan
	showEmpty         bool                            // True if no findings were found
	showHelp          bool                            // True when help overlay is shown

	// Search & Filter state
	searchMode     bool            // True when search input is active
	searchInput    textinput.Model // Text input for search
	searchQuery    string          // Current active search query
	severityFilter types.Severity  // Filter by severity ("" = no filter)

	// Sort state
	sortColumn  string // Current sort column: "severity", "path", "detector", "" (default)
	sortReverse bool   // True if sort is reversed

	// Selection state (for bulk operations)
	selectedFindings map[int]bool // Set of selected finding indices (in original findings)

	// Export mode state
	showExportMenu bool // True when export format menu is shown

	// Diff view state
	diffMode          bool            // True when showing diff view
	diffNewFindings   []types.Finding // Findings added since last scan
	diffFixedFindings []types.Finding // Findings removed since last scan
	diffPrevTimestamp time.Time       // Timestamp of the previous scan

	// Context expansion state
	contextLines int // Number of lines to show around finding (default 3)

	// Grouping state
	groupMode       string          // "none", "file", "detector"
	expandedGroups  map[string]bool // Set of expanded group keys
	groupedFindings []GroupedItem   // Flattened list for display (groups + findings)
	pendingKey      string          // For multi-key sequences like "gf", "gd"
}

// GroupedItem represents either a group header or a finding in the grouped view
type GroupedItem struct {
	IsGroup    bool           // True if this is a group header
	GroupKey   string         // Group identifier (file path or detector name)
	GroupCount int            // Number of findings in this group
	Finding    *types.Finding // Non-nil if this is a finding row
}

// SortColumn constants
const (
	SortDefault  = ""
	SortSeverity = "severity"
	SortPath     = "path"
	SortDetector = "detector"
)

// GroupMode constants
const (
	GroupNone       = "none"
	GroupByFile     = "file"
	GroupByDetector = "detector"
)

// NewModel initializes a new TUI model.
func NewModel(findings []types.Finding, rescanFunc func() ([]types.Finding, error)) Model {
	// Define table columns - use plain text (no ANSI) to avoid truncation issues
	columns := []table.Column{
		{Title: "Sev", Width: 8}, // "HIGH" or "(b) HIGH"
		{Title: "Detector", Width: 20},
		{Title: "Path", Width: 40},
		{Title: "Match", Width: 35},
	}

	// Prepare table rows from findings (no baseline marking here)
	// Use plain text for severity - ANSI codes cause truncation issues
	rows := make([]table.Row, len(findings))
	for i, f := range findings {
		rows[i] = table.Row{
			severityText(f.Severity),
			f.Detector,
			f.Path,
			f.Match,
		}
	}

	// Create table component
	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(10), // Initial height, will be adjusted
	)

	// Apply custom styles to the table - simplified
	s := table.DefaultStyles()
	s.Header = lipgloss.NewStyle().
		Background(lipgloss.Color("235")).
		Foreground(lipgloss.Color("15")).
		Bold(true).
		Padding(0, 1). // Add horizontal padding for better spacing
		Align(lipgloss.Left)

	s.Selected = lipgloss.NewStyle().
		Foreground(lipgloss.Color("232")). // Dark text for contrast
		Background(lipgloss.Color("208")). // Orange
		Bold(true).
		Padding(0, 1)

	s.Cell = lipgloss.NewStyle().
		Padding(0, 1) // Add consistent padding to all cells

	t.SetStyles(s)

	// Initialize spinner - use Line spinner for ASCII compatibility
	// (Dot uses Braille characters that render as diamonds on some terminals)
	sp := spinner.New()
	sp.Spinner = spinner.Line
	sp.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))

	// Initialize search input
	ti := textinput.New()
	ti.Placeholder = "Search path, detector, or match..."
	ti.CharLimit = 100
	ti.Width = 50
	ti.Prompt = "/ "
	ti.PromptStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	ti.TextStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("15"))

	// Initialize main model
	m := Model{
		table:            t,
		spinner:          sp,
		findings:         findings,
		rescanFunc:       rescanFunc,
		showEmpty:        len(findings) == 0,
		initialScanDone:  len(findings) > 0, // If we have findings, this wasn't the first ever scan
		hasScannedOnce:   true,              // We've already completed the initial scan to get here
		lastScanTime:     time.Now(),        // Set scan time to now
		searchInput:      ti,
		selectedFindings: make(map[int]bool),
		contextLines:     3,         // Default context lines around finding
		groupMode:        GroupNone, // No grouping by default
		expandedGroups:   make(map[string]bool),
	}

	if m.showEmpty {
		m.statusMessage = "q: quit | r: rescan | a: audit log"
	} else {
		m.statusMessage = "q: quit | ?: help | j/k: navigate | o: open | r: rescan | i: ignore | b: baseline"
	}

	// Viewport will be initialized in the first WindowSizeMsg
	return m
}

// NewModelWithBaseline initializes a TUI model with baseline awareness
func NewModelWithBaseline(findings []types.Finding, baseline report.Baseline, rescanFunc func() ([]types.Finding, error)) Model {
	// Build baselined set for fast lookup
	baselinedSet := make(map[string]bool)
	if baseline.Items != nil {
		for key := range baseline.Items {
			baselinedSet[key] = true
		}
	}

	// Use existing NewModel then add baseline info
	m := NewModel(findings, rescanFunc)
	m.baselinedSet = baselinedSet

	// Rebuild rows with baseline marking
	rows := make([]table.Row, len(findings))
	newCount := 0
	for i, f := range findings {
		dimmed := isBaselined(f, baselinedSet)
		if !dimmed {
			newCount++
		}

		// Dim baselined findings
		// Use plain text - table styling handles colors
		sev := severityText(f.Severity)
		if dimmed {
			sev = "(b) " + sev // Mark baselined with prefix instead of ANSI
		}

		rows[i] = table.Row{
			sev,
			f.Detector,
			f.Path,
			f.Match,
		}
	}
	m.table.SetRows(rows)

	// Update status to reflect baseline state
	if len(findings) > 0 && newCount == 0 {
		m.statusMessage = fmt.Sprintf("Showing %d baselined findings | q: quit | ?: help | r: rescan | a: audit log", len(findings))
	} else if newCount < len(findings) {
		m.statusMessage = fmt.Sprintf("%d new, %d baselined | q: quit | ?: help | j/k: navigate | o: open | i: ignore | b: baseline | a: audit", newCount, len(findings)-newCount)
	}

	return m
}

// Init can return a Cmd to immediately start an activity.
func (m Model) Init() tea.Cmd {
	return m.spinner.Tick
}

// rescan triggers a new scan, typically without cache.
func (m *Model) rescan() tea.Cmd {
	return func() tea.Msg {
		if m.rescanFunc == nil {
			return statusMsg("Rescan not available")
		}

		newFindings, err := m.rescanFunc()
		if err != nil {
			return statusMsg(fmt.Sprintf("Scan error: %v", err))
		}

		return findingsMsg(newFindings)
	}
}

// findingsMsg is a custom message type sent when new findings are available.
type findingsMsg []types.Finding

// applyFilters applies search query and severity filter to findings
func (m *Model) applyFilters() {
	// Check if any filters are active
	hasSearchFilter := m.searchQuery != ""
	hasSeverityFilter := m.severityFilter != ""

	if !hasSearchFilter && !hasSeverityFilter {
		// No filters - clear filtered state
		m.filteredFindings = nil
		m.filteredIndices = nil
		m.rebuildTableRows()
		return
	}

	// Apply filters
	var filtered []types.Finding
	var indices []int
	query := strings.ToLower(m.searchQuery)

	for i, f := range m.findings {
		// Check severity filter
		if hasSeverityFilter && f.Severity != m.severityFilter {
			continue
		}

		// Check search filter (case-insensitive match on path, detector, or match)
		if hasSearchFilter {
			pathMatch := strings.Contains(strings.ToLower(f.Path), query)
			detectorMatch := strings.Contains(strings.ToLower(f.Detector), query)
			matchMatch := strings.Contains(strings.ToLower(f.Match), query)
			if !pathMatch && !detectorMatch && !matchMatch {
				continue
			}
		}

		filtered = append(filtered, f)
		indices = append(indices, i)
	}

	m.filteredFindings = filtered
	m.filteredIndices = indices
	m.rebuildTableRows()
}

// clearFilters removes all active filters
func (m *Model) clearFilters() {
	m.searchQuery = ""
	m.severityFilter = ""
	m.filteredFindings = nil
	m.filteredIndices = nil
	m.rebuildTableRows()
}

// rebuildTableRows updates the table with current (filtered or all) findings
func (m *Model) rebuildTableRows() {
	// Handle grouped mode
	if m.groupMode != GroupNone {
		m.buildGroupedFindings()
		rows := make([]table.Row, len(m.groupedFindings))
		for i, item := range m.groupedFindings {
			if item.IsGroup {
				// Group header row
				expandIcon := "+"
				if m.expandedGroups[item.GroupKey] {
					expandIcon = "-"
				}
				groupLabel := fmt.Sprintf("%s [%d]", item.GroupKey, item.GroupCount)
				rows[i] = table.Row{
					expandIcon,
					"",
					groupLabel,
					"",
				}
			} else {
				// Finding row (indented)
				f := item.Finding
				sev := "  " + severityText(f.Severity) // Indent findings

				if isBaselined(*f, m.baselinedSet) {
					sev = "  (b) " + severityText(f.Severity)
				}

				// Show different info based on group mode
				var col2, col3 string
				if m.groupMode == GroupByFile {
					col2 = f.Detector
					col3 = fmt.Sprintf("L%d: %s", f.Line, f.Match)
				} else {
					col2 = f.Path
					col3 = f.Match
				}

				rows[i] = table.Row{
					sev,
					col2,
					col3,
					"",
				}
			}
		}
		m.table.SetRows(rows)
		if m.table.Cursor() >= len(m.groupedFindings) {
			m.table.SetCursor(0)
		}
		m.showEmpty = len(m.groupedFindings) == 0
		m.updateViewportContent()
		return
	}

	// Normal (ungrouped) mode
	findings := m.getDisplayFindings()
	rows := make([]table.Row, len(findings))
	for i, f := range findings {
		// Build severity text with selection and baseline indicators
		sev := severityText(f.Severity)

		// Add baseline indicator
		if isBaselined(f, m.baselinedSet) {
			sev = "(b) " + sev
		}

		// Add selection indicator (use [x] for selected, [ ] for not selected if any are selected)
		origIdx := m.getOriginalIndex(i)
		if len(m.selectedFindings) > 0 {
			if m.selectedFindings[origIdx] {
				sev = "[x] " + sev
			} else {
				sev = "[ ] " + sev
			}
		}

		rows[i] = table.Row{
			sev,
			f.Detector,
			f.Path,
			f.Match,
		}
	}
	m.table.SetRows(rows)
	// Only reset cursor if it's out of bounds
	if m.table.Cursor() >= len(findings) {
		m.table.SetCursor(0)
	}
	m.showEmpty = len(findings) == 0
	m.updateViewportContent()
}

// getDisplayFindings returns filtered findings if filter is active, otherwise all findings
func (m *Model) getDisplayFindings() []types.Finding {
	if m.filteredFindings != nil {
		return m.filteredFindings
	}
	return m.findings
}

// getOriginalIndex maps a display index to the original findings index
func (m *Model) getOriginalIndex(displayIdx int) int {
	if m.filteredIndices != nil {
		if displayIdx >= 0 && displayIdx < len(m.filteredIndices) {
			return m.filteredIndices[displayIdx]
		}
		return -1
	}
	return displayIdx
}

// jumpToNextSeverity jumps to the next finding with the given severity
// direction: 1 for forward, -1 for backward
// returns true if a match was found
func (m *Model) jumpToNextSeverity(severity types.Severity, direction int) bool {
	displayFindings := m.getDisplayFindings()
	if len(displayFindings) == 0 {
		return false
	}

	current := m.table.Cursor()
	n := len(displayFindings)

	// Search in the given direction, wrapping around
	for i := 1; i <= n; i++ {
		idx := (current + direction*i + n) % n
		if displayFindings[idx].Severity == severity {
			m.table.SetCursor(idx)
			return true
		}
	}
	return false
}

// severityRank returns a numeric rank for sorting (HIGH=0, MED=1, LOW=2)
func severityRank(s types.Severity) int {
	switch s {
	case types.SevHigh:
		return 0
	case types.SevMed:
		return 1
	case types.SevLow:
		return 2
	default:
		return 3
	}
}

// cycleSortColumn advances to the next sort column
func (m *Model) cycleSortColumn() {
	switch m.sortColumn {
	case SortDefault:
		m.sortColumn = SortSeverity
	case SortSeverity:
		m.sortColumn = SortPath
	case SortPath:
		m.sortColumn = SortDetector
	case SortDetector:
		m.sortColumn = SortDefault
	}
	m.sortReverse = false // Reset reverse when changing column
	m.sortFindings()
}

// toggleSortReverse reverses the current sort order
func (m *Model) toggleSortReverse() {
	m.sortReverse = !m.sortReverse
	m.sortFindings()
}

// sortFindings sorts m.findings according to current sort settings
func (m *Model) sortFindings() {
	if m.sortColumn == SortDefault {
		// Default order - no sorting needed, but we need to rebuild
		m.rebuildTableRows()
		return
	}

	// Create a stable sort
	sort.SliceStable(m.findings, func(i, j int) bool {
		var less bool
		switch m.sortColumn {
		case SortSeverity:
			less = severityRank(m.findings[i].Severity) < severityRank(m.findings[j].Severity)
		case SortPath:
			less = strings.ToLower(m.findings[i].Path) < strings.ToLower(m.findings[j].Path)
		case SortDetector:
			less = strings.ToLower(m.findings[i].Detector) < strings.ToLower(m.findings[j].Detector)
		default:
			return false
		}
		if m.sortReverse {
			return !less
		}
		return less
	})

	// Re-apply filters after sorting (this will rebuild table rows)
	m.applyFilters()
}

// getSortIndicator returns a visual indicator for the current sort state
func (m *Model) getSortIndicator() string {
	if m.sortColumn == SortDefault {
		return ""
	}
	arrow := "^" // Ascending
	if m.sortReverse {
		arrow = "v" // Descending
	}
	return fmt.Sprintf(" [%s %s]", m.sortColumn, arrow)
}

// computeDiff compares current findings with previous scan and populates diff fields
func (m *Model) computeDiff() bool {
	// Load audit history to get previous scan
	auditLog := audit.NewAuditLog(".")
	history, err := auditLog.LoadHistory()
	if err != nil || len(history) < 2 {
		// Need at least 2 scans to diff
		return false
	}

	// Current scan is history[0], previous is history[1]
	prevScan := history[1]
	m.diffPrevTimestamp = prevScan.Timestamp

	// Build a set of previous finding keys for fast lookup
	prevKeys := make(map[string]bool)
	for _, f := range prevScan.AllFindings {
		key := f.Path + "|" + f.Detector + "|" + f.Match
		prevKeys[key] = true
	}

	// Build a set of current finding keys
	currKeys := make(map[string]bool)
	for _, f := range m.findings {
		key := f.Path + "|" + f.Detector + "|" + f.Match
		currKeys[key] = true
	}

	// Find new findings (in current but not in previous)
	m.diffNewFindings = nil
	for _, f := range m.findings {
		key := f.Path + "|" + f.Detector + "|" + f.Match
		if !prevKeys[key] {
			m.diffNewFindings = append(m.diffNewFindings, f)
		}
	}

	// Find fixed findings (in previous but not in current)
	m.diffFixedFindings = nil
	for _, f := range prevScan.AllFindings {
		key := f.Path + "|" + f.Detector + "|" + f.Match
		if !currKeys[key] {
			m.diffFixedFindings = append(m.diffFixedFindings, f)
		}
	}

	return true
}

// exitDiffMode exits diff mode and returns to normal view
func (m *Model) exitDiffMode() {
	m.diffMode = false
	m.diffNewFindings = nil
	m.diffFixedFindings = nil
	m.rebuildTableRows()
}

// setGroupMode changes the grouping mode and rebuilds the view
func (m *Model) setGroupMode(mode string) {
	if m.groupMode == mode {
		// Toggle off if already in this mode
		m.groupMode = GroupNone
		m.groupedFindings = nil
		m.expandedGroups = make(map[string]bool)
	} else {
		m.groupMode = mode
		m.expandedGroups = make(map[string]bool)
		// Expand all groups by default
		m.buildGroupedFindings()
		for _, item := range m.groupedFindings {
			if item.IsGroup {
				m.expandedGroups[item.GroupKey] = true
			}
		}
	}
	m.rebuildTableRows()
}

// buildGroupedFindings builds the flattened list of groups and findings
func (m *Model) buildGroupedFindings() {
	if m.groupMode == GroupNone {
		m.groupedFindings = nil
		return
	}

	displayFindings := m.getDisplayFindings()

	// Group findings by the appropriate key
	groups := make(map[string][]types.Finding)
	var groupOrder []string // Preserve order of first occurrence

	for _, f := range displayFindings {
		var key string
		switch m.groupMode {
		case GroupByFile:
			key = f.Path
		case GroupByDetector:
			key = f.Detector
		default:
			continue
		}

		if _, exists := groups[key]; !exists {
			groupOrder = append(groupOrder, key)
		}
		groups[key] = append(groups[key], f)
	}

	// Build flattened list
	m.groupedFindings = nil
	for _, key := range groupOrder {
		findings := groups[key]
		// Add group header
		m.groupedFindings = append(m.groupedFindings, GroupedItem{
			IsGroup:    true,
			GroupKey:   key,
			GroupCount: len(findings),
		})

		// Add findings if group is expanded
		if m.expandedGroups[key] {
			for i := range findings {
				m.groupedFindings = append(m.groupedFindings, GroupedItem{
					IsGroup:  false,
					GroupKey: key,
					Finding:  &findings[i],
				})
			}
		}
	}
}

// toggleGroupExpansion toggles the expansion state of the current group
func (m *Model) toggleGroupExpansion() {
	if m.groupMode == GroupNone || len(m.groupedFindings) == 0 {
		return
	}

	idx := m.table.Cursor()
	if idx < 0 || idx >= len(m.groupedFindings) {
		return
	}

	item := m.groupedFindings[idx]
	groupKey := item.GroupKey

	// Toggle expansion
	m.expandedGroups[groupKey] = !m.expandedGroups[groupKey]
	m.buildGroupedFindings()
	m.rebuildTableRows()
}

// getGroupedDisplayItem returns the item at the given index in grouped mode
func (m *Model) getGroupedDisplayItem(idx int) *GroupedItem {
	if m.groupMode == GroupNone || idx < 0 || idx >= len(m.groupedFindings) {
		return nil
	}
	return &m.groupedFindings[idx]
}

// expandContext increases the number of context lines shown
func (m *Model) expandContext() {
	if m.contextLines < 20 {
		m.contextLines += 2
		if m.contextLines > 20 {
			m.contextLines = 20
		}
		m.updateViewportContent()
	}
}

// contractContext decreases the number of context lines shown
func (m *Model) contractContext() {
	if m.contextLines > 1 {
		m.contextLines -= 2
		if m.contextLines < 1 {
			m.contextLines = 1
		}
		m.updateViewportContent()
	}
}

// readFileContext reads lines from a file around the specified line number
func readFileContext(path string, targetLine int, contextLines int) ([]string, int, error) {
	// Check if this is a virtual path (contains ::)
	if strings.Contains(path, "::") {
		return nil, 0, fmt.Errorf("virtual path")
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	startLine := targetLine - contextLines
	if startLine < 1 {
		startLine = 1
	}
	endLine := targetLine + contextLines

	var lines []string
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum >= startLine && lineNum <= endLine {
			lines = append(lines, scanner.Text())
		}
		if lineNum > endLine {
			break
		}
	}

	return lines, startLine, scanner.Err()
}

// BlameInfo holds git blame information for a line
type BlameInfo struct {
	Author string
	Date   string
	Commit string
}

// getGitBlame gets blame info for a specific line in a file
func getGitBlame(path string, line int) *BlameInfo {
	// Check if this is a virtual path
	if strings.Contains(path, "::") {
		return nil
	}

	// Run git blame for just the specific line
	// -L specifies line range, -p for porcelain format
	cmd := fmt.Sprintf("git blame -L %d,%d --porcelain -- %q 2>/dev/null", line, line, path)
	out, err := runCommand(cmd)
	if err != nil || out == "" {
		return nil
	}

	// Parse porcelain format
	lines := strings.Split(out, "\n")
	if len(lines) < 2 {
		return nil
	}

	info := &BlameInfo{}

	// First line has commit hash
	parts := strings.Fields(lines[0])
	if len(parts) > 0 {
		info.Commit = parts[0][:8] // Short hash
	}

	// Parse the rest for author and date
	for _, line := range lines {
		if strings.HasPrefix(line, "author ") {
			info.Author = strings.TrimPrefix(line, "author ")
		} else if strings.HasPrefix(line, "author-time ") {
			// Unix timestamp
			timeStr := strings.TrimPrefix(line, "author-time ")
			if ts, err := parseUnixTimestamp(timeStr); err == nil {
				info.Date = ts.Format("2006-01-02")
			}
		}
	}

	return info
}

// runCommand executes a shell command and returns the output
func runCommand(cmd string) (string, error) {
	out, err := execCommand("sh", "-c", cmd)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// execCommand is a wrapper around os/exec for testing
var execCommand = func(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}

// parseUnixTimestamp parses a unix timestamp string
func parseUnixTimestamp(s string) (time.Time, error) {
	var ts int64
	if _, err := fmt.Sscanf(s, "%d", &ts); err != nil {
		return time.Time{}, err
	}
	return time.Unix(ts, 0), nil
}

// highlightCode applies syntax highlighting to code based on file extension
// Returns the original code if highlighting fails
func highlightCode(code string, filename string) string {
	// Get lexer based on filename
	lexer := lexers.Match(filename)
	if lexer == nil {
		// Try to match by extension for virtual paths
		ext := filepath.Ext(filename)
		if ext != "" {
			lexer = lexers.Match("file" + ext)
		}
	}
	if lexer == nil {
		lexer = lexers.Fallback
	}

	// Coalesce runs of identical token types for cleaner output
	lexer = chroma.Coalesce(lexer)

	// Use a terminal-friendly style
	style := styles.Get("monokai")
	if style == nil {
		style = styles.Fallback
	}

	// Use terminal256 formatter for ANSI colors
	formatter := formatters.Get("terminal256")
	if formatter == nil {
		formatter = formatters.Fallback
	}

	// Tokenize and format
	iterator, err := lexer.Tokenise(nil, code)
	if err != nil {
		return code
	}

	var buf bytes.Buffer
	err = formatter.Format(&buf, style, iterator)
	if err != nil {
		return code
	}

	return buf.String()
}

// highlightLine applies syntax highlighting to a single line of code
func highlightLine(line string, filename string) string {
	// Get lexer based on filename
	lexer := lexers.Match(filename)
	if lexer == nil {
		ext := filepath.Ext(filename)
		if ext != "" {
			lexer = lexers.Match("file" + ext)
		}
	}
	if lexer == nil {
		return line // No highlighting for unknown file types
	}

	lexer = chroma.Coalesce(lexer)

	style := styles.Get("monokai")
	if style == nil {
		style = styles.Fallback
	}

	formatter := formatters.Get("terminal256")
	if formatter == nil {
		return line
	}

	iterator, err := lexer.Tokenise(nil, line)
	if err != nil {
		return line
	}

	var buf bytes.Buffer
	if err := formatter.Format(&buf, style, iterator); err != nil {
		return line
	}

	// Remove trailing newline that chroma might add
	result := buf.String()
	result = strings.TrimSuffix(result, "\n")
	return result
}

// toggleSelection toggles selection on the currently displayed finding
func (m *Model) toggleSelection() {
	idx := m.table.Cursor()
	origIdx := m.getOriginalIndex(idx)
	if origIdx < 0 {
		return
	}
	if m.selectedFindings[origIdx] {
		delete(m.selectedFindings, origIdx)
	} else {
		m.selectedFindings[origIdx] = true
	}
	m.rebuildTableRows()
	// Restore cursor position
	m.table.SetCursor(idx)
}

// selectAll selects all visible (filtered) findings
func (m *Model) selectAll() {
	displayFindings := m.getDisplayFindings()
	for i := range displayFindings {
		origIdx := m.getOriginalIndex(i)
		if origIdx >= 0 {
			m.selectedFindings[origIdx] = true
		}
	}
	m.rebuildTableRows()
}

// deselectAll deselects all findings
func (m *Model) deselectAll() {
	m.selectedFindings = make(map[int]bool)
	m.rebuildTableRows()
}

// toggleSelectAll either selects all or deselects all based on current state
func (m *Model) toggleSelectAll() {
	displayFindings := m.getDisplayFindings()
	// Check if all visible are selected
	allSelected := true
	for i := range displayFindings {
		origIdx := m.getOriginalIndex(i)
		if origIdx >= 0 && !m.selectedFindings[origIdx] {
			allSelected = false
			break
		}
	}
	if allSelected {
		m.deselectAll()
	} else {
		m.selectAll()
	}
}

// getSelectedCount returns the number of selected findings
func (m *Model) getSelectedCount() int {
	return len(m.selectedFindings)
}

// isSelected checks if a finding at display index is selected
func (m *Model) isSelected(displayIdx int) bool {
	origIdx := m.getOriginalIndex(displayIdx)
	return origIdx >= 0 && m.selectedFindings[origIdx]
}

// updateViewportContent updates the detail view with the currently selected finding.
func (m *Model) updateViewportContent() {
	// Handle grouped mode
	if m.groupMode != GroupNone {
		if len(m.groupedFindings) == 0 || !m.ready {
			m.viewport.SetContent("")
			return
		}

		idx := m.table.Cursor()
		if idx >= 0 && idx < len(m.groupedFindings) {
			item := m.groupedFindings[idx]

			if item.IsGroup {
				// Show group summary
				var b strings.Builder
				b.WriteString(fmt.Sprintf("%s\n\n", titleStyle.Render("Group Summary")))
				b.WriteString(fmt.Sprintf("%s %s\n", keyStyle.Render("Group:"), item.GroupKey))
				b.WriteString(fmt.Sprintf("%s %d\n", keyStyle.Render("Findings:"), item.GroupCount))

				expanded := m.expandedGroups[item.GroupKey]
				if expanded {
					b.WriteString(fmt.Sprintf("\n%s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Render("Press Tab to collapse this group")))
				} else {
					b.WriteString(fmt.Sprintf("\n%s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Render("Press Tab to expand this group")))
				}

				m.viewport.SetContent(b.String())
				return
			}

			// It's a finding within a group - show the finding details
			if item.Finding == nil {
				m.viewport.SetContent("")
				return
			}
			// Fall through to normal finding display with the grouped finding
			m.updateViewportContentForFinding(*item.Finding)
			return
		}
		m.viewport.SetContent("")
		return
	}

	// Normal mode
	displayFindings := m.getDisplayFindings()
	if len(displayFindings) == 0 || !m.ready {
		m.viewport.SetContent("")
		return
	}

	idx := m.table.Cursor()
	if idx >= 0 && idx < len(displayFindings) {
		f := displayFindings[idx]
		m.updateViewportContentForFinding(f)
	}
}

// updateViewportContentForFinding renders finding details in the viewport
func (m *Model) updateViewportContentForFinding(f types.Finding) {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s\n\n", titleStyle.Render("Finding Details")))

	// Check if this finding is baselined
	baselined := isBaselined(f, m.baselinedSet)
	if baselined {
		baselineStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("8")).
			Italic(true)
		b.WriteString(baselineStyle.Render("BASELINED: This finding is known/accepted. Press 'U' to remove from baseline."))
		b.WriteString("\n\n")
	}

	// Check for virtual path and show archive context
	isVirtual := strings.Contains(f.Path, "::")
	if isVirtual {
		virtualStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("11")). // Yellow
			Italic(true)
		b.WriteString(virtualStyle.Render("VIRTUAL FILE: This finding is inside an archive/container."))
		b.WriteString("\n")
		b.WriteString(virtualStyle.Render("Press 'o' will not work - file cannot be opened directly."))
		b.WriteString("\n\n")

		// Parse and display archive context
		parts := strings.Split(f.Path, "::")
		if len(parts) >= 2 {
			b.WriteString(fmt.Sprintf("%s %s\n", keyStyle.Render("Archive:"), parts[0]))
			if len(parts) == 2 {
				b.WriteString(fmt.Sprintf("%s %s\n", keyStyle.Render("File:"), parts[1]))
			} else {
				// Multiple layers (e.g., container::layer::file)
				b.WriteString(fmt.Sprintf("%s %s\n", keyStyle.Render("Layer:"), parts[1]))
				b.WriteString(fmt.Sprintf("%s %s\n", keyStyle.Render("File:"), strings.Join(parts[2:], "::")))
			}
		} else {
			b.WriteString(fmt.Sprintf("%s %s\n", keyStyle.Render("Path:"), f.Path))
		}
	} else {
		b.WriteString(fmt.Sprintf("%s %s\n", keyStyle.Render("Path:"), f.Path))
	}

	// Render finding details using keyStyle for labels
	b.WriteString(fmt.Sprintf("%s %s\n", keyStyle.Render("Detector:"), f.Detector))
	b.WriteString(fmt.Sprintf("%s %s\n", keyStyle.Render("Severity:"), f.Severity))
	b.WriteString(fmt.Sprintf("%s %d\n", keyStyle.Render("Line:"), f.Line))
	if f.Column > 0 {
		b.WriteString(fmt.Sprintf("%s %d\n", keyStyle.Render("Column:"), f.Column))
	}
	if f.Secret != "" {
		b.WriteString(fmt.Sprintf("%s %s\n", keyStyle.Render("Secret:"), f.Secret))
	}
	if len(f.Metadata) > 0 {
		b.WriteString(fmt.Sprintf("%s\n", keyStyle.Render("Metadata:")))
		for k, v := range f.Metadata {
			b.WriteString(fmt.Sprintf("  %s: %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Render(k), v))
		}
	}

	// Git commit info (only for non-virtual files)
	if !isVirtual {
		if blame := getGitBlame(f.Path, f.Line); blame != nil {
			commitStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("6")) // Cyan
			commitText := fmt.Sprintf("%s (%s, %s)", blame.Commit, blame.Author, blame.Date)
			b.WriteString(fmt.Sprintf("%s %s\n", keyStyle.Render("Commit:"), commitStyle.Render(commitText)))
		}
	}

	// Context section header with expand/contract hint
	contextHint := fmt.Sprintf(" (+/- to expand/contract, showing %d lines)", m.contextLines*2+1)
	b.WriteString(fmt.Sprintf("\n%s%s\n",
		keyStyle.Render("Context:"),
		lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Render(contextHint)))

	// Try to read expanded context from file
	lines, startLine, err := readFileContext(f.Path, f.Line, m.contextLines)
	if err == nil && len(lines) > 0 {
		// Render context with line numbers and syntax highlighting
		lineNumStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
		highlightLineStyle := lipgloss.NewStyle().Background(lipgloss.Color("236"))

		// Get the filename for syntax highlighting (handle virtual paths)
		filename := f.Path
		if strings.Contains(filename, "::") {
			// Extract the actual filename from virtual path
			parts := strings.Split(filename, "::")
			filename = parts[len(parts)-1]
		}

		for i, line := range lines {
			lineNum := startLine + i
			lineNumStr := lineNumStyle.Render(fmt.Sprintf("%4d ", lineNum))

			// Apply syntax highlighting to the line
			highlightedLine := highlightLine(line, filename)

			// Highlight the line containing the finding
			if lineNum == f.Line {
				// For the finding line, we need to highlight the match specially
				// Apply match highlighting on top of syntax highlighting
				if f.Match != "" {
					// Use a distinctive style for the match that stands out
					highlightedLine = strings.ReplaceAll(highlightedLine, f.Match, matchStyle.Render(f.Match))
				}
				b.WriteString(lineNumStr + highlightLineStyle.Render(highlightedLine) + "\n")
			} else {
				b.WriteString(lineNumStr + highlightedLine + "\n")
			}
		}
	} else {
		// Fallback to original context or match
		context := f.Context
		if context == "" {
			context = f.Match // Fallback to match if no context
		}

		// Apply syntax highlighting to fallback context
		filename := f.Path
		if strings.Contains(filename, "::") {
			parts := strings.Split(filename, "::")
			filename = parts[len(parts)-1]
		}
		context = highlightCode(context, filename)

		// Highlight the matched string within the context
		if f.Match != "" {
			context = strings.ReplaceAll(context, f.Match, matchStyle.Render(f.Match))
		}
		b.WriteString(context)
	}

	m.viewport.SetContent(b.String())
}

// Update handles incoming messages (events) and updates the model state.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.KeyMsg:
		// If help is showing, any key closes it (except the ones that open it)
		if m.showHelp {
			switch msg.String() {
			case "?", "h":
				m.showHelp = false
			default:
				// Any other key closes help
				m.showHelp = false
			}
			return m, nil
		}

		// If scan history popup is showing, handle it separately
		if m.showScanHistory {
			switch msg.String() {
			case "q", "esc", "a":
				m.showScanHistory = false
				m.historySelection = 0
			case "up", "k":
				if m.historySelection > 0 {
					m.historySelection--
				}
			case "down", "j":
				if m.historySelection < len(m.scanHistory)-1 {
					m.historySelection++
				}
			case "enter":
				// Load selected historical scan
				if m.historySelection >= 0 && m.historySelection < len(m.scanHistory) {
					selected := m.scanHistory[m.historySelection]
					m.findings = selected.AllFindings
					m.lastScanTime = selected.Timestamp
					m.viewingHistorical = true
					m.showScanHistory = false

					// Rebuild table rows with plain text
					rows := make([]table.Row, len(m.findings))
					for i, f := range m.findings {
						rows[i] = table.Row{
							severityText(f.Severity),
							f.Detector,
							f.Path,
							f.Match,
						}
					}
					m.table.SetRows(rows)
					m.updateViewportContent()

					// Update status
					timeout := time.Now().Add(5 * time.Second)
					m.statusTimeout = &timeout
					m.statusMessage = fmt.Sprintf("Loaded historical scan from %s", selected.Timestamp.Format("Jan 2, 15:04"))
				}
			case "d", "x", "backspace", "delete":
				// Delete selected scan from history
				if m.historySelection >= 0 && m.historySelection < len(m.scanHistory) {
					auditLog := audit.NewAuditLog(".")
					if err := auditLog.DeleteRecord(m.historySelection); err == nil {
						// Reload history
						if history, err := auditLog.LoadHistory(); err == nil {
							m.scanHistory = history
							// Adjust selection if needed
							if m.historySelection >= len(m.scanHistory) {
								m.historySelection = len(m.scanHistory) - 1
							}
							if m.historySelection < 0 {
								m.historySelection = 0
							}
						}
					}
				}
			}
			return m, nil
		}

		// If export menu is showing, handle format selection
		if m.showExportMenu {
			switch msg.String() {
			case "1", "j": // JSON
				m.showExportMenu = false
				return m, m.exportFindings("json")
			case "2", "c": // CSV
				m.showExportMenu = false
				return m, m.exportFindings("csv")
			case "3", "s": // SARIF
				m.showExportMenu = false
				return m, m.exportFindings("sarif")
			case "esc", "q", "e":
				m.showExportMenu = false
				return m, nil
			}
			return m, nil
		}

		// If search mode is active, handle text input
		if m.searchMode {
			switch msg.String() {
			case "enter":
				// Confirm search and exit search mode
				m.searchQuery = m.searchInput.Value()
				m.searchMode = false
				m.searchInput.Blur()
				// Filters already applied via live search
				return m, nil
			case "esc":
				// Cancel search - restore previous query
				m.searchMode = false
				m.searchInput.Blur()
				m.searchInput.SetValue(m.searchQuery) // Restore previous query
				m.applyFilters()                      // Re-apply with old query
				return m, nil
			default:
				// Forward to text input
				m.searchInput, cmd = m.searchInput.Update(msg)
				// Live filtering as user types
				m.searchQuery = m.searchInput.Value()
				m.applyFilters()
				return m, cmd
			}
		}

		// Handle pending key sequences (like "gf", "gd")
		if m.pendingKey == "g" {
			m.pendingKey = ""
			switch msg.String() {
			case "f": // gf - group by file
				m.setGroupMode(GroupByFile)
				timeout := time.Now().Add(3 * time.Second)
				m.statusTimeout = &timeout
				if m.groupMode == GroupByFile {
					m.statusMessage = "Grouped by file (Tab to expand/collapse, gf to ungroup)"
				} else {
					m.statusMessage = "Grouping disabled"
				}
				return m, nil
			case "d": // gd - group by detector
				m.setGroupMode(GroupByDetector)
				timeout := time.Now().Add(3 * time.Second)
				m.statusTimeout = &timeout
				if m.groupMode == GroupByDetector {
					m.statusMessage = "Grouped by detector (Tab to expand/collapse, gd to ungroup)"
				} else {
					m.statusMessage = "Grouping disabled"
				}
				return m, nil
			case "g": // gg - go to top (vim style)
				if !m.showEmpty {
					m.table.GotoTop()
					m.updateViewportContent()
				}
				return m, nil
			default:
				// Unknown sequence, just ignore
				return m, nil
			}
		}

		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "/": // Enter search mode
			if !m.showEmpty || len(m.findings) > 0 {
				m.searchMode = true
				m.searchInput.SetValue(m.searchQuery) // Start with current query
				m.searchInput.Focus()
				return m, textinput.Blink
			}
		case "1": // Filter to HIGH severity
			m.severityFilter = types.SevHigh
			m.applyFilters()
			timeout := time.Now().Add(3 * time.Second)
			m.statusTimeout = &timeout
			m.statusMessage = "Showing HIGH severity only (Esc to clear)"
			return m, nil
		case "2": // Filter to MED severity
			m.severityFilter = types.SevMed
			m.applyFilters()
			timeout := time.Now().Add(3 * time.Second)
			m.statusTimeout = &timeout
			m.statusMessage = "Showing MED severity only (Esc to clear)"
			return m, nil
		case "3": // Filter to LOW severity
			m.severityFilter = types.SevLow
			m.applyFilters()
			timeout := time.Now().Add(3 * time.Second)
			m.statusTimeout = &timeout
			m.statusMessage = "Showing LOW severity only (Esc to clear)"
			return m, nil
		case "esc": // Clear filters or exit diff mode
			if m.diffMode {
				m.exitDiffMode()
				timeout := time.Now().Add(3 * time.Second)
				m.statusTimeout = &timeout
				m.statusMessage = "Exited diff view"
				return m, nil
			}
			if m.searchQuery != "" || m.severityFilter != "" {
				m.clearFilters()
				timeout := time.Now().Add(3 * time.Second)
				m.statusTimeout = &timeout
				m.statusMessage = "Filters cleared"
				return m, nil
			}
		case "n": // Jump to next HIGH severity finding
			if !m.showEmpty {
				if m.jumpToNextSeverity(types.SevHigh, 1) {
					m.updateViewportContent()
				} else {
					timeout := time.Now().Add(2 * time.Second)
					m.statusTimeout = &timeout
					m.statusMessage = "No more HIGH findings"
				}
				return m, nil
			}
		case "N": // Jump to previous HIGH severity finding
			if !m.showEmpty {
				if m.jumpToNextSeverity(types.SevHigh, -1) {
					m.updateViewportContent()
				} else {
					timeout := time.Now().Add(2 * time.Second)
					m.statusTimeout = &timeout
					m.statusMessage = "No more HIGH findings"
				}
				return m, nil
			}
		case "s": // Cycle sort column
			if len(m.findings) > 0 {
				m.cycleSortColumn()
				timeout := time.Now().Add(3 * time.Second)
				m.statusTimeout = &timeout
				if m.sortColumn == SortDefault {
					m.statusMessage = "Sort: default order"
				} else {
					m.statusMessage = fmt.Sprintf("Sort by %s (S to reverse)", m.sortColumn)
				}
				return m, nil
			}
		case "S": // Reverse sort
			if len(m.findings) > 0 && m.sortColumn != SortDefault {
				m.toggleSortReverse()
				timeout := time.Now().Add(3 * time.Second)
				m.statusTimeout = &timeout
				direction := "ascending"
				if m.sortReverse {
					direction = "descending"
				}
				m.statusMessage = fmt.Sprintf("Sort by %s (%s)", m.sortColumn, direction)
				return m, nil
			}
		case "v": // Toggle selection on current finding
			if !m.showEmpty {
				m.toggleSelection()
				timeout := time.Now().Add(2 * time.Second)
				m.statusTimeout = &timeout
				count := m.getSelectedCount()
				if count == 0 {
					m.statusMessage = "Selection cleared"
				} else {
					m.statusMessage = fmt.Sprintf("%d selected (V: all, B: baseline, Ctrl+i: ignore)", count)
				}
				return m, nil
			}
		case "V": // Select/deselect all visible findings
			if !m.showEmpty {
				m.toggleSelectAll()
				timeout := time.Now().Add(2 * time.Second)
				m.statusTimeout = &timeout
				count := m.getSelectedCount()
				if count == 0 {
					m.statusMessage = "All deselected"
				} else {
					m.statusMessage = fmt.Sprintf("All %d selected (B: baseline, Ctrl+i: ignore)", count)
				}
				return m, nil
			}
		case "B": // Bulk baseline selected findings
			if len(m.selectedFindings) > 0 {
				cmd := m.bulkBaseline()
				m.rebuildTableRows()
				return m, cmd
			}
			timeout := time.Now().Add(2 * time.Second)
			m.statusTimeout = &timeout
			m.statusMessage = "No findings selected (press v to select)"
			return m, nil
		case "ctrl+i": // Bulk ignore selected files
			if len(m.selectedFindings) > 0 {
				cmd := m.bulkIgnore()
				m.rebuildTableRows()
				return m, cmd
			}
			timeout := time.Now().Add(2 * time.Second)
			m.statusTimeout = &timeout
			m.statusMessage = "No findings selected (press v to select)"
			return m, nil
		case "o", "enter":
			if !m.showEmpty {
				return m, m.openEditor()
			}
		case "i":
			if !m.showEmpty {
				return m, m.ignoreFile()
			}
		case "I": // Unignore - remove from .redactylignore
			if !m.showEmpty {
				return m, m.unignoreFile()
			}
		case "b":
			if !m.showEmpty {
				return m, m.addToBaseline()
			}
		case "U": // Unbaseline - remove from baseline (capital U)
			if !m.showEmpty {
				return m, m.removeFromBaseline()
			}
		case "e": // Export menu
			if len(m.getDisplayFindings()) > 0 {
				m.showExportMenu = true
				return m, nil
			}
		case "+", "=": // Expand context (= is unshifted + on most keyboards)
			if !m.showEmpty {
				m.expandContext()
				timeout := time.Now().Add(2 * time.Second)
				m.statusTimeout = &timeout
				m.statusMessage = fmt.Sprintf("Context: %d lines", m.contextLines*2+1)
				return m, nil
			}
		case "-", "_": // Contract context
			if !m.showEmpty {
				m.contractContext()
				timeout := time.Now().Add(2 * time.Second)
				m.statusTimeout = &timeout
				m.statusMessage = fmt.Sprintf("Context: %d lines", m.contextLines*2+1)
				return m, nil
			}
		case "y": // Copy path to clipboard
			if !m.showEmpty {
				return m, m.copyPathToClipboard()
			}
		case "Y": // Copy full finding to clipboard
			if !m.showEmpty {
				return m, m.copyFindingToClipboard()
			}
		case "D": // Toggle diff mode
			if m.diffMode {
				m.exitDiffMode()
				timeout := time.Now().Add(3 * time.Second)
				m.statusTimeout = &timeout
				m.statusMessage = "Exited diff view"
				return m, nil
			}
			if m.computeDiff() {
				m.diffMode = true
				timeout := time.Now().Add(5 * time.Second)
				m.statusTimeout = &timeout
				m.statusMessage = fmt.Sprintf("Diff: %d new, %d fixed since %s",
					len(m.diffNewFindings), len(m.diffFixedFindings),
					m.diffPrevTimestamp.Format("Jan 2, 15:04"))
			} else {
				timeout := time.Now().Add(3 * time.Second)
				m.statusTimeout = &timeout
				m.statusMessage = "Need at least 2 scans to show diff"
			}
			return m, nil
		case "tab": // Toggle group expansion
			if m.groupMode != GroupNone {
				m.toggleGroupExpansion()
				return m, nil
			}
		case "r": // Rescan key
			if m.rescanFunc == nil {
				// No rescan function provided
				timeout := time.Now().Add(3 * time.Second)
				m.statusTimeout = &timeout
				m.statusMessage = "Rescan not available"
				return m, nil
			}
			if !m.scanning { // Allow rescan anytime (not just when empty)
				m.scanning = true
				m.hasScannedOnce = true // Mark that we've initiated a scan
				scanMsg := "Scanning..."
				if m.hasScannedOnce {
					scanMsg = "Rescanning..."
				}
				m.statusMessage = scanMsg
				return m, m.rescan()
			}
		case "a": // Toggle scan history popup
			if !m.showScanHistory {
				// Load history when opening popup
				auditLog := audit.NewAuditLog(".")
				history, err := auditLog.LoadHistory()
				if err == nil {
					m.scanHistory = history
					m.historySelection = 0
				}
			}
			m.showScanHistory = !m.showScanHistory
		case "?", "h": // Show help
			m.showHelp = !m.showHelp
			return m, nil
		case "down", "j":
			if !m.showEmpty {
				m.table, cmd = m.table.Update(msg)
				m.updateViewportContent()
				return m, cmd
			}
		case "up", "k":
			if !m.showEmpty {
				m.table, cmd = m.table.Update(msg)
				m.updateViewportContent()
				return m, cmd
			}
		case "ctrl+d": // Half-page down in table (vim style)
			if !m.showEmpty {
				halfPage := m.table.Height() / 2
				if halfPage < 1 {
					halfPage = 1
				}
				m.table.MoveDown(halfPage)
				m.updateViewportContent()
				return m, nil
			}
		case "ctrl+u": // Half-page up in table (vim style)
			if !m.showEmpty {
				halfPage := m.table.Height() / 2
				if halfPage < 1 {
					halfPage = 1
				}
				m.table.MoveUp(halfPage)
				m.updateViewportContent()
				return m, nil
			}
		case "ctrl+f", "pgdown": // Full page down in table
			if !m.showEmpty {
				m.table.MoveDown(m.table.Height())
				m.updateViewportContent()
				return m, nil
			}
		case "ctrl+b", "pgup": // Full page up in table
			if !m.showEmpty {
				m.table.MoveUp(m.table.Height())
				m.updateViewportContent()
				return m, nil
			}
		case "g": // Start pending key sequence for grouping (gf, gd) or go to top (gg)
			m.pendingKey = "g"
			return m, nil
		case "home": // Jump to top of table
			if !m.showEmpty {
				m.table.GotoTop()
				m.updateViewportContent()
				return m, nil
			}
		case "G", "end": // Jump to bottom of table
			if !m.showEmpty {
				m.table.GotoBottom()
				m.updateViewportContent()
				return m, nil
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.ready = true

		// Dynamic column widths for table with better spacing
		// Account for borders, separators, and padding (approximately 10 chars)
		usableWidth := m.width - 10
		sevWidth := 8       // Severity column (fits "HIGH" or "(b) HIGH")
		detectorWidth := 20 // Detector column

		// Remaining width split between Path (45%) and Match (55%)
		remainingWidth := usableWidth - sevWidth - detectorWidth
		pathWidth := int(float64(remainingWidth) * 0.45)
		matchWidth := remainingWidth - pathWidth

		// Ensure minimum widths
		if pathWidth < 25 {
			pathWidth = 25
		}
		if matchWidth < 25 {
			matchWidth = 25
		}

		cols := m.table.Columns()
		cols[0].Width = sevWidth
		cols[1].Width = detectorWidth
		cols[2].Width = pathWidth
		cols[3].Width = matchWidth
		m.table.SetColumns(cols)

		// Calculate heights for table, viewport, stats header, and status bar
		// Account for stats header (1 line) and status bar
		statsHeaderHeight := 1
		availableHeight := m.height - lipgloss.Height(statusStyle.Render("")) - statsHeaderHeight

		tableHeight := int(float64(availableHeight) * 0.45)
		viewportHeight := availableHeight - tableHeight - detailPaneBorderStyle.GetVerticalFrameSize() - 1

		m.table.SetWidth(m.width)
		m.table.SetHeight(tableHeight)

		// Initialize/resize viewport
		if m.viewport.Height == 0 { // Check if not initialized yet
			m.viewport = viewport.New(m.width, viewportHeight)
		} else {
			m.viewport.Width = m.width
			m.viewport.Height = viewportHeight
		}
		m.updateViewportContent()

		// Update status bar width
		statusStyle = statusStyle.Width(m.width)

	case findingsMsg: // Received new findings after a rescan
		m.findings = msg
		m.showEmpty = len(m.findings) == 0
		m.lastScanTime = time.Now() // Update scan timestamp
		m.viewingCached = false     // No longer viewing cached results after rescan

		// Re-populate table with new findings

		rows := make([]table.Row, len(m.findings))
		for i, f := range m.findings {
			rows[i] = table.Row{
				severityText(f.Severity),
				f.Detector,
				f.Path,
				f.Match,
			}
		}
		m.table.SetRows(rows)

		// Reset table cursor if findings are cleared
		if m.showEmpty {
			m.table.SetCursor(0)
		}
		m.updateViewportContent()

		// Update status message based on new findings with timeout
		m.scanning = false      // Scan complete
		m.hasScannedOnce = true // Mark that we've completed a scan
		timeout := time.Now().Add(5 * time.Second)
		m.statusTimeout = &timeout
		if m.showEmpty {
			m.statusMessage = "Rescan complete - no new secrets found"
		} else {
			m.statusMessage = fmt.Sprintf("Rescan complete - found %d findings", len(m.findings))
		}

	case statusMsg: // Received a status update message
		timeout := time.Now().Add(3 * time.Second)
		m.statusTimeout = &timeout
		m.statusMessage = string(msg)

	case spinner.TickMsg:
		var spinCmd tea.Cmd
		m.spinner, spinCmd = m.spinner.Update(msg)

		// Clear status timeout if expired
		if m.statusTimeout != nil && time.Now().After(*m.statusTimeout) {
			m.statusTimeout = nil
			// Restore default status message
			if m.showEmpty {
				m.statusMessage = "q: quit | r: rescan"
			} else {
				m.statusMessage = "q: quit | ?: help | j/k: navigate | o: open | r: rescan | i: ignore | b: baseline"
			}
		}
		return m, spinCmd
	}

	// Update table (for navigation not handled by custom keybindings)
	if !m.quitting && !m.showEmpty {
		shouldUpdate := true
		if keyMsg, ok := msg.(tea.KeyMsg); ok {
			key := keyMsg.String()
			if key == "down" || key == "j" || key == "up" || key == "k" {
				shouldUpdate = false
			}
		}
		if shouldUpdate {
			m.table, cmd = m.table.Update(msg)
		}
	}

	// Always sync viewport content with current selection (e.g. if table updated itself implicitly)
	m.updateViewportContent()

	return m, cmd
}

// View renders the current state of the model to the terminal.
func (m Model) View() string {
	if m.quitting {
		return "" // Exit clean
	}
	if !m.ready {
		return "Initializing..." // Show loading until dimensions are known
	}

	// If scanning, show the scanning overlay
	if m.scanning {
		var msgContent string
		// Determine if this is initial scan or rescan
		scanType := "Scanning"
		if m.hasScannedOnce {
			scanType = "Rescanning"
		}
		msgContent = fmt.Sprintf("%s  %s...\n\nPlease wait", m.spinner.View(), scanType)

		// Use a minimum width for the popup to prevent cramped text
		minPopupWidth := 55

		// Render the popup box and center it
		popupBox := popupStyle.
			Width(minPopupWidth).
			Align(lipgloss.Center).
			Render(msgContent)

		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, popupBox)
	}

	// Calculate stats from display findings (respects filters)
	displayFindings := m.getDisplayFindings()
	var highCount, medCount, lowCount int
	for _, f := range displayFindings {
		switch f.Severity {
		case types.SevHigh:
			highCount++
		case types.SevMed:
			medCount++
		case types.SevLow:
			lowCount++
		}
	}

	// Render stats header with counts
	var statsContent string
	if len(m.findings) == 0 {
		// No findings to display
		if m.viewingCached {
			statsContent = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Render("[OK] All findings baselined")
		} else {
			statsContent = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Render("[OK] No secrets detected")
		}
	} else {
		// Build filter indicator
		var filterInfo string
		if m.searchQuery != "" || m.severityFilter != "" {
			var parts []string
			if m.searchQuery != "" {
				parts = append(parts, fmt.Sprintf("search:'%s'", m.searchQuery))
			}
			if m.severityFilter != "" {
				parts = append(parts, fmt.Sprintf("sev:%s", severityText(m.severityFilter)))
			}
			filterInfo = fmt.Sprintf("  [FILTER: %s]", strings.Join(parts, ", "))
		}

		// Build sort indicator
		sortInfo := m.getSortIndicator()

		// Build selection indicator
		var selectionInfo string
		if len(m.selectedFindings) > 0 {
			selectionInfo = fmt.Sprintf("  [%d selected]", len(m.selectedFindings))
		}

		// Show counts - use filtered count if filter active
		if m.filteredFindings != nil {
			statsContent = fmt.Sprintf(
				"Showing: %d/%d  |  %s %-4d  |  %s %-4d  |  %s %-4d%s%s%s",
				len(displayFindings),
				len(m.findings),
				sevHighStyle.Render("High:"),
				highCount,
				sevMedStyle.Render("Med:"),
				medCount,
				sevLowStyle.Render("Low:"),
				lowCount,
				filterInfo,
				sortInfo,
				selectionInfo,
			)
		} else {
			statsContent = fmt.Sprintf(
				"Total: %-4d  |  %s %-4d  |  %s %-4d  |  %s %-4d%s%s",
				len(m.findings),
				sevHighStyle.Render("High:"),
				highCount,
				sevMedStyle.Render("Med:"),
				medCount,
				sevLowStyle.Render("Low:"),
				lowCount,
				sortInfo,
				selectionInfo,
			)
		}
	}

	statsHeader := lipgloss.NewStyle().
		Width(m.width).
		Padding(0, 2).
		Foreground(lipgloss.Color("15")).
		Background(lipgloss.Color("237")).
		Render(statsContent)

	// Render main TUI layout (table, detail pane, status bar)
	tableRender := tableBorderStyle.
		Width(m.width).
		Height(m.table.Height()).
		Render(m.table.View())

	// Detail pane - show message if no findings (or no matches after filter)
	var detailContent string
	if len(displayFindings) == 0 {
		var emptyMsg string
		if len(m.findings) == 0 {
			emptyMsg = "No secrets to review.\n\nPress 'r' to rescan\nPress '?' for help"
		} else {
			// Filtering resulted in no matches
			emptyMsg = "No findings match filter.\n\nPress 'Esc' to clear filter"
		}
		detailContent = lipgloss.Place(
			m.width,
			m.viewport.Height,
			lipgloss.Center,
			lipgloss.Center,
			emptyTextStyle.Render(emptyMsg),
		)
	} else {
		detailContent = m.viewport.View()
	}

	detailRender := detailPaneBorderStyle.
		Width(m.width).
		Height(m.viewport.Height).
		Render(detailContent)

	// Build status bar: commands on left, timestamp on right
	var timeInfo string
	if m.viewingHistorical {
		timeInfo = fmt.Sprintf("Viewing: %s", m.lastScanTime.Format("Jan 2, 15:04"))
	} else if !m.lastScanTime.IsZero() {
		timeAgo := time.Since(m.lastScanTime)
		timeInfo = fmt.Sprintf("Scanned: %s ago", formatDuration(timeAgo))
	}

	// Calculate spacing between status message and timestamp
	statusLeft := m.statusMessage
	statusRight := timeInfo
	leftWidth := lipgloss.Width(statusLeft)
	rightWidth := lipgloss.Width(statusRight)
	availWidth := m.width - 4 // Account for some padding
	spacer := availWidth - leftWidth - rightWidth
	if spacer < 1 {
		spacer = 1
	}

	var statusContent string
	if timeInfo != "" {
		statusContent = statusLeft + strings.Repeat(" ", spacer) + statusRight
	} else {
		statusContent = statusLeft
	}

	statusRender := statusStyle.
		Width(m.width).
		Padding(0, 2).
		Render(statusContent)

	// Build bottom bar - either search input (vim-style) or status bar
	var bottomBar string
	if m.searchMode {
		// Vim-style search bar at bottom
		matchCount := len(m.getDisplayFindings())
		searchStatus := fmt.Sprintf(" (%d matches)", matchCount)
		searchBarStyle := lipgloss.NewStyle().
			Background(lipgloss.Color("235")).
			Foreground(lipgloss.Color("15")).
			Width(m.width).
			Padding(0, 1)
		// Show search input with match count
		bottomBar = searchBarStyle.Render(m.searchInput.View() + searchStatus)
	} else {
		bottomBar = statusRender
	}

	// Build main view
	mainView := lipgloss.JoinVertical(lipgloss.Left,
		statsHeader,
		tableRender,
		detailRender,
		bottomBar,
	)

	// Show help overlay if requested
	if m.showHelp {
		// Styles for help screen
		titleStyle := lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("15"))

		sectionStyle := lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("12"))

		keyColor := lipgloss.Color("10")   // Green for keys
		descColor := lipgloss.Color("250") // Light gray for descriptions

		// Helper to format a row with fixed-width key column
		formatRow := func(key, desc string) string {
			keyStyled := lipgloss.NewStyle().Foreground(keyColor).Render(key)
			descStyled := lipgloss.NewStyle().Foreground(descColor).Render(desc)
			// Pad key to 12 chars for alignment (accounting for no ANSI in padding calc)
			padding := 12 - len(key)
			if padding < 1 {
				padding = 1
			}
			return "  " + keyStyled + strings.Repeat(" ", padding) + descStyled
		}

		var lines []string

		// Title
		lines = append(lines, titleStyle.Render("Keyboard Shortcuts"))
		lines = append(lines, "")

		// Navigation
		lines = append(lines, sectionStyle.Render("Navigation"))
		lines = append(lines, formatRow("j / k", "Move down / up"))
		lines = append(lines, formatRow("Ctrl+d/u", "Half-page down / up"))
		lines = append(lines, formatRow("Ctrl+f/b", "Full page down / up"))
		lines = append(lines, formatRow("g / G", "First / last row"))
		lines = append(lines, formatRow("n / N", "Next / prev HIGH finding"))
		lines = append(lines, "")

		// Search & Filter
		lines = append(lines, sectionStyle.Render("Search & Filter"))
		lines = append(lines, formatRow("/", "Search findings"))
		lines = append(lines, formatRow("1 / 2 / 3", "Filter HIGH / MED / LOW"))
		lines = append(lines, formatRow("s / S", "Sort / reverse sort"))
		lines = append(lines, formatRow("Esc", "Clear filters"))
		lines = append(lines, "")

		// Selection & Bulk
		lines = append(lines, sectionStyle.Render("Selection & Bulk"))
		lines = append(lines, formatRow("v / V", "Select one / select all"))
		lines = append(lines, formatRow("B", "Bulk baseline selected"))
		lines = append(lines, formatRow("Ctrl+i", "Bulk ignore selected"))
		lines = append(lines, "")

		// Export & Copy
		lines = append(lines, sectionStyle.Render("Export & Copy"))
		lines = append(lines, formatRow("e", "Export (JSON/CSV/SARIF)"))
		lines = append(lines, formatRow("y / Y", "Copy path / full finding"))
		lines = append(lines, "")

		// Context
		lines = append(lines, sectionStyle.Render("Context"))
		lines = append(lines, formatRow("+ / -", "Expand / contract context"))
		lines = append(lines, "")

		// Actions
		lines = append(lines, sectionStyle.Render("Actions"))
		lines = append(lines, formatRow("Enter", "Open in $EDITOR"))
		lines = append(lines, formatRow("i / I", "Ignore / unignore file"))
		lines = append(lines, formatRow("b / U", "Baseline / unbaseline"))
		lines = append(lines, formatRow("r", "Rescan"))
		lines = append(lines, "")

		// Grouping
		lines = append(lines, sectionStyle.Render("Grouping"))
		lines = append(lines, formatRow("gf", "Group by file"))
		lines = append(lines, formatRow("gd", "Group by detector"))
		lines = append(lines, formatRow("Tab", "Expand/collapse group"))
		lines = append(lines, "")

		// Diff & History
		lines = append(lines, sectionStyle.Render("Diff & History"))
		lines = append(lines, formatRow("D", "Diff vs previous scan"))
		lines = append(lines, formatRow("a", "View audit history"))
		lines = append(lines, "")

		// Other
		lines = append(lines, sectionStyle.Render("Other"))
		lines = append(lines, formatRow("?", "Toggle help"))
		lines = append(lines, formatRow("q", "Quit"))
		lines = append(lines, "")

		// Footer
		lines = append(lines, lipgloss.NewStyle().
			Foreground(lipgloss.Color("8")).
			Italic(true).
			Render("Press any key to close"))

		helpContent := lipgloss.JoinVertical(lipgloss.Left, lines...)

		helpBox := popupStyle.
			Width(44).
			Padding(1, 3).
			Render(helpContent)

		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, helpBox)
	}

	// Show export menu popup if requested
	if m.showExportMenu {
		titleStyle := lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("15"))

		keyColor := lipgloss.Color("10")
		descColor := lipgloss.Color("250")

		var lines []string
		lines = append(lines, titleStyle.Render("Export Findings"))
		lines = append(lines, "")
		lines = append(lines, fmt.Sprintf("  %s  JSON  (human readable)",
			lipgloss.NewStyle().Foreground(keyColor).Bold(true).Render("1/j")))
		lines = append(lines, fmt.Sprintf("  %s  CSV   (spreadsheet)",
			lipgloss.NewStyle().Foreground(keyColor).Bold(true).Render("2/c")))
		lines = append(lines, fmt.Sprintf("  %s  SARIF (CI/CD integration)",
			lipgloss.NewStyle().Foreground(keyColor).Bold(true).Render("3/s")))
		lines = append(lines, "")
		lines = append(lines, lipgloss.NewStyle().
			Foreground(descColor).
			Italic(true).
			Render(fmt.Sprintf("Exporting %d findings", len(m.getDisplayFindings()))))
		lines = append(lines, "")
		lines = append(lines, lipgloss.NewStyle().
			Foreground(lipgloss.Color("8")).
			Italic(true).
			Render("Esc to cancel"))

		exportContent := lipgloss.JoinVertical(lipgloss.Left, lines...)
		exportBox := popupStyle.
			Width(40).
			Padding(1, 3).
			Render(exportContent)

		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, exportBox)
	}

	// Show diff view popup if requested
	if m.diffMode {
		titleStyle := lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("15"))

		newStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("9")). // Red for new findings
			Bold(true)

		fixedStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("10")). // Green for fixed findings
			Bold(true)

		dimStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("8"))

		var lines []string
		lines = append(lines, titleStyle.Render(fmt.Sprintf("DIFF: %s vs Current",
			m.diffPrevTimestamp.Format("Jan 2, 15:04"))))
		lines = append(lines, "")

		// Summary line
		summaryParts := []string{}
		if len(m.diffNewFindings) > 0 {
			summaryParts = append(summaryParts,
				newStyle.Render(fmt.Sprintf("+%d new", len(m.diffNewFindings))))
		}
		if len(m.diffFixedFindings) > 0 {
			summaryParts = append(summaryParts,
				fixedStyle.Render(fmt.Sprintf("-%d fixed", len(m.diffFixedFindings))))
		}
		if len(summaryParts) == 0 {
			lines = append(lines, dimStyle.Render("No changes between scans"))
		} else {
			lines = append(lines, strings.Join(summaryParts, "  "))
		}
		lines = append(lines, "")

		// New findings section
		if len(m.diffNewFindings) > 0 {
			lines = append(lines, newStyle.Render("NEW FINDINGS (added since last scan):"))
			maxShow := 8
			if len(m.diffNewFindings) < maxShow {
				maxShow = len(m.diffNewFindings)
			}
			for i := 0; i < maxShow; i++ {
				f := m.diffNewFindings[i]
				line := fmt.Sprintf("  + [%s] %s:%d  %s",
					severityText(f.Severity),
					f.Path,
					f.Line,
					f.Detector)
				lines = append(lines, newStyle.Render(line))
			}
			if len(m.diffNewFindings) > maxShow {
				lines = append(lines, dimStyle.Render(
					fmt.Sprintf("  ... and %d more", len(m.diffNewFindings)-maxShow)))
			}
			lines = append(lines, "")
		}

		// Fixed findings section
		if len(m.diffFixedFindings) > 0 {
			lines = append(lines, fixedStyle.Render("FIXED FINDINGS (removed since last scan):"))
			maxShow := 8
			if len(m.diffFixedFindings) < maxShow {
				maxShow = len(m.diffFixedFindings)
			}
			for i := 0; i < maxShow; i++ {
				f := m.diffFixedFindings[i]
				line := fmt.Sprintf("  - [%s] %s:%d  %s",
					severityText(f.Severity),
					f.Path,
					f.Line,
					f.Detector)
				lines = append(lines, fixedStyle.Render(line))
			}
			if len(m.diffFixedFindings) > maxShow {
				lines = append(lines, dimStyle.Render(
					fmt.Sprintf("  ... and %d more", len(m.diffFixedFindings)-maxShow)))
			}
			lines = append(lines, "")
		}

		lines = append(lines, "")
		lines = append(lines, dimStyle.Italic(true).Render("Press D or Esc to close"))

		diffContent := lipgloss.JoinVertical(lipgloss.Left, lines...)
		diffBox := popupStyle.
			Width(70).
			Padding(2, 3).
			Render(diffContent)

		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, diffBox)
	}

	// Show scan history popup if requested
	if m.showScanHistory {
		titleStyle := lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("15")).
			Render("SCAN HISTORY")

		// Try to load audit log
		auditLog := audit.NewAuditLog(".")
		history, err := auditLog.LoadHistory()

		var content string
		if err != nil || len(history) == 0 {
			content = lipgloss.NewStyle().
				Foreground(lipgloss.Color("8")).
				Render("No scan history found.\n\nRun scans to build audit history.")
		} else {
			var lines []string
			lines = append(lines, titleStyle)
			lines = append(lines, "")

			// Show up to 10 most recent scans
			maxScans := 10
			if len(history) < maxScans {
				maxScans = len(history)
			}

			for i := 0; i < maxScans; i++ {
				scan := history[i]
				timeStr := scan.Timestamp.Format("Jan 2, 15:04:05")

				summaryStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("7"))
				if scan.TotalFindings == 0 {
					summaryStyle = summaryStyle.Foreground(lipgloss.Color("10")) // Green
				} else if scan.NewFindings > 0 {
					summaryStyle = summaryStyle.Foreground(lipgloss.Color("11")) // Yellow
				}

				summary := fmt.Sprintf("%s - %d findings (%d new, %d baselined)",
					timeStr, scan.TotalFindings, scan.NewFindings, scan.BaselinedCount)

				// Highlight selected scan
				if i == m.historySelection {
					lines = append(lines, lipgloss.NewStyle().
						Foreground(lipgloss.Color("232")).
						Background(lipgloss.Color("208")). // Orange
						Bold(true).
						Render("  > "+summary))
				} else {
					lines = append(lines, summaryStyle.Render("    "+summary))
				}
			}

			lines = append(lines, "")
			lines = append(lines, "")
			lines = append(lines, lipgloss.NewStyle().
				Foreground(lipgloss.Color("8")).
				Italic(true).
				Render("Enter: view | d: delete | a: close"))

			content = lipgloss.JoinVertical(lipgloss.Left, lines...)
		}

		historyBox := popupStyle.
			Width(70).
			Padding(2, 4).
			Render(content)

		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, historyBox)
	}

	return mainView
}
