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

var (
	tableBorderStyle = lipgloss.NewStyle().
				BorderStyle(lipgloss.NormalBorder()).
				BorderForeground(lipgloss.Color("240"))

	detailPaneBorderStyle = lipgloss.NewStyle().
				BorderStyle(lipgloss.NormalBorder()).
				BorderForeground(lipgloss.Color("240"))

	titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("6")).
			Bold(true).
			Padding(0, 1)

	matchStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("9")).
			Bold(true)

	keyStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("7")).
			Bold(true)

	statusStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("236")).
			Foreground(lipgloss.Color("7"))

	emptyTextStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("15")).
			Align(lipgloss.Center)

	popupStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("12")).
			Background(lipgloss.Color("235")).
			Padding(1, 4)

	sevHighStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	sevMedStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	sevLowStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
)

// severityText returns plain text for severity (ANSI codes break table truncation).
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

func isBaselined(f types.Finding, baselinedSet map[string]bool) bool {
	if baselinedSet == nil {
		return false
	}
	key := f.Path + "|" + f.Detector + "|" + f.Match
	return baselinedSet[key]
}

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

	// Secret visibility state
	hideSecrets bool // When true, redact secret values in display (default true)

	// Grouping state
	groupMode       string          // "none", "file", "detector"
	expandedGroups  map[string]bool // Set of expanded group keys
	groupedFindings []GroupedItem   // Flattened list for display (groups + findings)
	pendingKey      string          // For multi-key sequences like "gf", "gd"

	// Clear history confirmation state
	showClearConfirm  bool // True when first confirmation is shown
	clearConfirmStage int  // 0=none, 1=first confirm, 2=second confirm
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
	// Load user preferences
	prefs := LoadPrefs()

	columns := []table.Column{
		{Title: "Sev", Width: 8},
		{Title: "Detector", Width: 20},
		{Title: "Path", Width: 40},
		{Title: "Match", Width: 35},
	}

	rows := make([]table.Row, len(findings))
	for i, f := range findings {
		match := f.Match
		if prefs.HideSecrets {
			match = redactSecret(match)
		}
		rows[i] = table.Row{
			severityText(f.Severity),
			f.Detector,
			f.Path,
			match,
		}
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(10),
	)

	s := table.DefaultStyles()
	s.Header = lipgloss.NewStyle().
		Background(lipgloss.Color("235")).
		Foreground(lipgloss.Color("15")).
		Bold(true).
		Padding(0, 1).
		Align(lipgloss.Left)

	s.Selected = lipgloss.NewStyle().
		Foreground(lipgloss.Color("232")).
		Background(lipgloss.Color("208")).
		Bold(true).
		Padding(0, 1)

	s.Cell = lipgloss.NewStyle().
		Padding(0, 1)

	t.SetStyles(s)

	// Line spinner avoids Braille characters that render poorly on some terminals
	sp := spinner.New()
	sp.Spinner = spinner.Line
	sp.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))

	ti := textinput.New()
	ti.Placeholder = "Search path, detector, or match..."
	ti.CharLimit = 100
	ti.Width = 50
	ti.Prompt = "/ "
	ti.PromptStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	ti.TextStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("15"))

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
		contextLines:     3,                 // Default context lines around finding
		hideSecrets:      prefs.HideSecrets, // Load from preferences (default: true)
		groupMode:        GroupNone,         // No grouping by default
		expandedGroups:   make(map[string]bool),
	}

	// Default legend - will be updated with actual width on WindowSizeMsg
	m.statusMessage = buildLegend(80, m.showEmpty, m.hideSecrets)

	return m
}

// NewModelWithBaseline initializes a TUI model with baseline awareness.
func NewModelWithBaseline(findings []types.Finding, baseline report.Baseline, rescanFunc func() ([]types.Finding, error)) Model {
	baselinedSet := make(map[string]bool)
	if baseline.Items != nil {
		for key := range baseline.Items {
			baselinedSet[key] = true
		}
	}

	m := NewModel(findings, rescanFunc)
	m.baselinedSet = baselinedSet

	rows := make([]table.Row, len(findings))
	newCount := 0
	for i, f := range findings {
		dimmed := isBaselined(f, baselinedSet)
		if !dimmed {
			newCount++
		}

		sev := severityText(f.Severity)
		if dimmed {
			sev = "(b) " + sev
		}

		match := f.Match
		if m.hideSecrets {
			match = redactSecret(match)
		}
		rows[i] = table.Row{
			sev,
			f.Detector,
			f.Path,
			match,
		}
	}
	m.table.SetRows(rows)

	// Legend will be set properly on first WindowSizeMsg, use default for now
	// The baseline counts are shown in the stats header instead

	return m
}

func (m Model) Init() tea.Cmd {
	return m.spinner.Tick
}

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

type findingsMsg []types.Finding

func (m *Model) applyFilters() {
	hasSearchFilter := m.searchQuery != ""
	hasSeverityFilter := m.severityFilter != ""

	if !hasSearchFilter && !hasSeverityFilter {
		m.filteredFindings = nil
		m.filteredIndices = nil
		m.rebuildTableRows()
		return
	}

	var filtered []types.Finding
	var indices []int
	query := strings.ToLower(m.searchQuery)

	for i, f := range m.findings {
		if hasSeverityFilter && f.Severity != m.severityFilter {
			continue
		}

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

func (m *Model) clearFilters() {
	m.searchQuery = ""
	m.severityFilter = ""
	m.filteredFindings = nil
	m.filteredIndices = nil
	m.rebuildTableRows()
}

func (m *Model) rebuildTableRows() {
	if m.groupMode != GroupNone {
		m.buildGroupedFindings()
		rows := make([]table.Row, len(m.groupedFindings))
		for i, item := range m.groupedFindings {
			if item.IsGroup {
				expandIcon := "+"
				if m.expandedGroups[item.GroupKey] {
					expandIcon = "-"
				}
				groupLabel := fmt.Sprintf("%s [%d]", item.GroupKey, item.GroupCount)
				rows[i] = table.Row{expandIcon, "", groupLabel, ""}
			} else {
				f := item.Finding
				sev := "  " + severityText(f.Severity)
				if isBaselined(*f, m.baselinedSet) {
					sev = "  (b) " + severityText(f.Severity)
				}

				var col2, col3 string
				if m.groupMode == GroupByFile {
					col2 = f.Detector
					matchDisplay := f.Match
					if m.hideSecrets {
						matchDisplay = redactSecret(matchDisplay)
					}
					col3 = fmt.Sprintf("L%d: %s", f.Line, matchDisplay)
				} else {
					col2 = f.Path
					col3 = f.Match
					if m.hideSecrets {
						col3 = redactSecret(col3)
					}
				}

				rows[i] = table.Row{sev, col2, col3, ""}
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

	findings := m.getDisplayFindings()
	rows := make([]table.Row, len(findings))
	for i, f := range findings {
		sev := severityText(f.Severity)

		if isBaselined(f, m.baselinedSet) {
			sev = "(b) " + sev
		}

		origIdx := m.getOriginalIndex(i)
		if len(m.selectedFindings) > 0 {
			if m.selectedFindings[origIdx] {
				sev = "[x] " + sev
			} else {
				sev = "[ ] " + sev
			}
		}

		match := f.Match
		if m.hideSecrets {
			match = redactSecret(match)
		}
		rows[i] = table.Row{sev, f.Detector, f.Path, match}
	}
	m.table.SetRows(rows)
	if m.table.Cursor() >= len(findings) {
		m.table.SetCursor(0)
	}
	m.showEmpty = len(findings) == 0
	m.updateViewportContent()
}

func (m *Model) getDisplayFindings() []types.Finding {
	if m.filteredFindings != nil {
		return m.filteredFindings
	}
	return m.findings
}

func (m *Model) getOriginalIndex(displayIdx int) int {
	if m.filteredIndices != nil {
		if displayIdx >= 0 && displayIdx < len(m.filteredIndices) {
			return m.filteredIndices[displayIdx]
		}
		return -1
	}
	return displayIdx
}

// jumpToNextSeverity finds next finding with given severity (direction: 1=forward, -1=backward).
func (m *Model) jumpToNextSeverity(severity types.Severity, direction int) bool {
	displayFindings := m.getDisplayFindings()
	if len(displayFindings) == 0 {
		return false
	}

	current := m.table.Cursor()
	n := len(displayFindings)

	for i := 1; i <= n; i++ {
		idx := (current + direction*i + n) % n
		if displayFindings[idx].Severity == severity {
			m.table.SetCursor(idx)
			return true
		}
	}
	return false
}

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
	m.sortReverse = false
	m.sortFindings()
}

func (m *Model) toggleSortReverse() {
	m.sortReverse = !m.sortReverse
	m.sortFindings()
}

func (m *Model) sortFindings() {
	if m.sortColumn == SortDefault {
		m.rebuildTableRows()
		return
	}

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

	m.applyFilters()
}

func (m *Model) getSortIndicator() string {
	if m.sortColumn == SortDefault {
		return ""
	}
	arrow := "^"
	if m.sortReverse {
		arrow = "v"
	}
	return fmt.Sprintf(" [%s %s]", m.sortColumn, arrow)
}

func (m *Model) computeDiff() bool {
	auditLog := audit.NewAuditLog(".")
	history, err := auditLog.LoadHistory()
	if err != nil || len(history) < 2 {
		return false
	}

	prevScan := history[1]
	m.diffPrevTimestamp = prevScan.Timestamp

	prevKeys := make(map[string]bool)
	for _, f := range prevScan.AllFindings {
		key := f.Path + "|" + f.Detector + "|" + f.Match
		prevKeys[key] = true
	}

	currKeys := make(map[string]bool)
	for _, f := range m.findings {
		key := f.Path + "|" + f.Detector + "|" + f.Match
		currKeys[key] = true
	}

	m.diffNewFindings = nil
	for _, f := range m.findings {
		key := f.Path + "|" + f.Detector + "|" + f.Match
		if !prevKeys[key] {
			m.diffNewFindings = append(m.diffNewFindings, f)
		}
	}

	m.diffFixedFindings = nil
	for _, f := range prevScan.AllFindings {
		key := f.Path + "|" + f.Detector + "|" + f.Match
		if !currKeys[key] {
			m.diffFixedFindings = append(m.diffFixedFindings, f)
		}
	}

	return true
}

func (m *Model) exitDiffMode() {
	m.diffMode = false
	m.diffNewFindings = nil
	m.diffFixedFindings = nil
	m.rebuildTableRows()
}

func (m *Model) setGroupMode(mode string) {
	if m.groupMode == mode {
		m.groupMode = GroupNone
		m.groupedFindings = nil
		m.expandedGroups = make(map[string]bool)
	} else {
		m.groupMode = mode
		m.expandedGroups = make(map[string]bool)
		m.buildGroupedFindings()
		for _, item := range m.groupedFindings {
			if item.IsGroup {
				m.expandedGroups[item.GroupKey] = true
			}
		}
	}
	m.rebuildTableRows()
}

func (m *Model) buildGroupedFindings() {
	if m.groupMode == GroupNone {
		m.groupedFindings = nil
		return
	}

	displayFindings := m.getDisplayFindings()

	groups := make(map[string][]types.Finding)
	var groupOrder []string

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

	m.groupedFindings = nil
	for _, key := range groupOrder {
		findings := groups[key]
		m.groupedFindings = append(m.groupedFindings, GroupedItem{
			IsGroup:    true,
			GroupKey:   key,
			GroupCount: len(findings),
		})

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

	m.expandedGroups[groupKey] = !m.expandedGroups[groupKey]
	m.buildGroupedFindings()
	m.rebuildTableRows()
}

func (m *Model) getGroupedDisplayItem(idx int) *GroupedItem {
	if m.groupMode == GroupNone || idx < 0 || idx >= len(m.groupedFindings) {
		return nil
	}
	return &m.groupedFindings[idx]
}

func (m *Model) expandContext() {
	if m.contextLines < 20 {
		m.contextLines += 2
		if m.contextLines > 20 {
			m.contextLines = 20
		}
		m.updateViewportContent()
	}
}

func (m *Model) contractContext() {
	if m.contextLines > 1 {
		m.contextLines -= 2
		if m.contextLines < 1 {
			m.contextLines = 1
		}
		m.updateViewportContent()
	}
}

func readFileContext(path string, targetLine int, contextLines int) ([]string, int, error) {
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

type BlameInfo struct {
	Author string
	Date   string
	Commit string
}

func getGitBlame(path string, line int) *BlameInfo {
	if strings.Contains(path, "::") {
		return nil
	}

	cmd := fmt.Sprintf("git blame -L %d,%d --porcelain -- %q 2>/dev/null", line, line, path)
	out, err := runCommand(cmd)
	if err != nil || out == "" {
		return nil
	}

	lines := strings.Split(out, "\n")
	if len(lines) < 2 {
		return nil
	}

	info := &BlameInfo{}

	parts := strings.Fields(lines[0])
	if len(parts) > 0 {
		info.Commit = parts[0][:8]
	}

	for _, line := range lines {
		if strings.HasPrefix(line, "author ") {
			info.Author = strings.TrimPrefix(line, "author ")
		} else if strings.HasPrefix(line, "author-time ") {
			timeStr := strings.TrimPrefix(line, "author-time ")
			if ts, err := parseUnixTimestamp(timeStr); err == nil {
				info.Date = ts.Format("2006-01-02")
			}
		}
	}

	return info
}

func runCommand(cmd string) (string, error) {
	out, err := execCommand("sh", "-c", cmd)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

var execCommand = func(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}

func parseUnixTimestamp(s string) (time.Time, error) {
	var ts int64
	if _, err := fmt.Sscanf(s, "%d", &ts); err != nil {
		return time.Time{}, err
	}
	return time.Unix(ts, 0), nil
}

func highlightCode(code string, filename string) string {
	lexer := lexers.Match(filename)
	if lexer == nil {
		ext := filepath.Ext(filename)
		if ext != "" {
			lexer = lexers.Match("file" + ext)
		}
	}
	if lexer == nil {
		lexer = lexers.Fallback
	}

	lexer = chroma.Coalesce(lexer)

	style := styles.Get("monokai")
	if style == nil {
		style = styles.Fallback
	}

	formatter := formatters.Get("terminal256")
	if formatter == nil {
		formatter = formatters.Fallback
	}

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

func highlightLine(line string, filename string) string {
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

	result := buf.String()
	result = strings.TrimSuffix(result, "\n")
	return result
}

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
	m.table.SetCursor(idx)
}

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

func (m *Model) deselectAll() {
	m.selectedFindings = make(map[int]bool)
	m.rebuildTableRows()
}

func (m *Model) toggleSelectAll() {
	displayFindings := m.getDisplayFindings()
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

func (m *Model) getSelectedCount() int {
	return len(m.selectedFindings)
}

func (m *Model) isSelected(displayIdx int) bool {
	origIdx := m.getOriginalIndex(displayIdx)
	return origIdx >= 0 && m.selectedFindings[origIdx]
}

func (m *Model) updateViewportContent() {
	if m.groupMode != GroupNone {
		if len(m.groupedFindings) == 0 || !m.ready {
			m.viewport.SetContent("")
			return
		}

		idx := m.table.Cursor()
		if idx >= 0 && idx < len(m.groupedFindings) {
			item := m.groupedFindings[idx]

			if item.IsGroup {
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

			if item.Finding == nil {
				m.viewport.SetContent("")
				return
			}
			m.updateViewportContentForFinding(*item.Finding)
			return
		}
		m.viewport.SetContent("")
		return
	}

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

func (m *Model) updateViewportContentForFinding(f types.Finding) {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s\n\n", titleStyle.Render("Finding Details")))

	baselined := isBaselined(f, m.baselinedSet)
	if baselined {
		baselineStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("8")).
			Italic(true)
		b.WriteString(baselineStyle.Render("BASELINED: This finding is known/accepted. Press 'U' to remove from baseline."))
		b.WriteString("\n\n")
	}

	isVirtual := strings.Contains(f.Path, "::")
	if isVirtual {
		virtualStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("11")).
			Italic(true)
		b.WriteString(virtualStyle.Render("VIRTUAL FILE: This finding is inside an archive/container."))
		b.WriteString("\n")
		b.WriteString(virtualStyle.Render("Press 'o' will not work - file cannot be opened directly."))
		b.WriteString("\n\n")

		parts := strings.Split(f.Path, "::")
		if len(parts) >= 2 {
			b.WriteString(fmt.Sprintf("%s %s\n", keyStyle.Render("Archive:"), parts[0]))
			if len(parts) == 2 {
				b.WriteString(fmt.Sprintf("%s %s\n", keyStyle.Render("File:"), parts[1]))
			} else {
				b.WriteString(fmt.Sprintf("%s %s\n", keyStyle.Render("Layer:"), parts[1]))
				b.WriteString(fmt.Sprintf("%s %s\n", keyStyle.Render("File:"), strings.Join(parts[2:], "::")))
			}
		} else {
			b.WriteString(fmt.Sprintf("%s %s\n", keyStyle.Render("Path:"), f.Path))
		}
	} else {
		b.WriteString(fmt.Sprintf("%s %s\n", keyStyle.Render("Path:"), f.Path))
	}

	b.WriteString(fmt.Sprintf("%s %s\n", keyStyle.Render("Detector:"), f.Detector))
	b.WriteString(fmt.Sprintf("%s %s\n", keyStyle.Render("Severity:"), f.Severity))
	b.WriteString(fmt.Sprintf("%s %d\n", keyStyle.Render("Line:"), f.Line))
	if f.Column > 0 {
		b.WriteString(fmt.Sprintf("%s %d\n", keyStyle.Render("Column:"), f.Column))
	}
	if f.Secret != "" {
		secretDisplay := f.Secret
		if m.hideSecrets {
			secretDisplay = redactSecret(secretDisplay)
		}
		b.WriteString(fmt.Sprintf("%s %s\n", keyStyle.Render("Secret:"), secretDisplay))
	}
	if len(f.Metadata) > 0 {
		b.WriteString(fmt.Sprintf("%s\n", keyStyle.Render("Metadata:")))
		for k, v := range f.Metadata {
			b.WriteString(fmt.Sprintf("  %s: %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Render(k), v))
		}
	}

	if !isVirtual {
		if blame := getGitBlame(f.Path, f.Line); blame != nil {
			commitStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
			commitText := fmt.Sprintf("%s (%s, %s)", blame.Commit, blame.Author, blame.Date)
			b.WriteString(fmt.Sprintf("%s %s\n", keyStyle.Render("Commit:"), commitStyle.Render(commitText)))
		}
	}

	contextHint := fmt.Sprintf(" (+/- to expand/contract, showing %d lines)", m.contextLines*2+1)
	b.WriteString(fmt.Sprintf("\n%s%s\n",
		keyStyle.Render("Context:"),
		lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Render(contextHint)))

	lines, startLine, err := readFileContext(f.Path, f.Line, m.contextLines)
	if err == nil && len(lines) > 0 {
		lineNumStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
		highlightLineStyle := lipgloss.NewStyle().Background(lipgloss.Color("236"))

		filename := f.Path
		if strings.Contains(filename, "::") {
			parts := strings.Split(filename, "::")
			filename = parts[len(parts)-1]
		}

		for i, line := range lines {
			lineNum := startLine + i
			lineNumStr := lineNumStyle.Render(fmt.Sprintf("%4d ", lineNum))

			// When hiding secrets, redact the match in the source line
			displayLine := line
			if m.hideSecrets && f.Match != "" {
				displayLine = strings.ReplaceAll(displayLine, f.Match, redactSecret(f.Match))
			}
			highlightedLine := highlightLine(displayLine, filename)

			if lineNum == f.Line {
				if f.Match != "" {
					matchDisplay := f.Match
					if m.hideSecrets {
						matchDisplay = redactSecret(f.Match)
					}
					highlightedLine = strings.ReplaceAll(highlightedLine, matchDisplay, matchStyle.Render(matchDisplay))
				}
				b.WriteString(lineNumStr + highlightLineStyle.Render(highlightedLine) + "\n")
			} else {
				b.WriteString(lineNumStr + highlightedLine + "\n")
			}
		}
	} else {
		context := f.Context
		if context == "" {
			context = f.Match
		}

		// Redact secret in context if hiding
		if m.hideSecrets && f.Match != "" {
			context = strings.ReplaceAll(context, f.Match, redactSecret(f.Match))
		}

		filename := f.Path
		if strings.Contains(filename, "::") {
			parts := strings.Split(filename, "::")
			filename = parts[len(parts)-1]
		}
		context = highlightCode(context, filename)

		if f.Match != "" {
			matchDisplay := f.Match
			if m.hideSecrets {
				matchDisplay = redactSecret(f.Match)
			}
			context = strings.ReplaceAll(context, matchDisplay, matchStyle.Render(matchDisplay))
		}
		b.WriteString(context)
	}

	m.viewport.SetContent(b.String())
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.showHelp {
			switch msg.String() {
			case "?", "h":
				m.showHelp = false
			default:
				m.showHelp = false
			}
			return m, nil
		}

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
				if m.historySelection >= 0 && m.historySelection < len(m.scanHistory) {
					selected := m.scanHistory[m.historySelection]
					m.findings = selected.AllFindings
					m.lastScanTime = selected.Timestamp
					m.viewingHistorical = true
					m.showScanHistory = false

					rows := make([]table.Row, len(m.findings))
					for i, f := range m.findings {
						match := f.Match
						if m.hideSecrets {
							match = redactSecret(match)
						}
						rows[i] = table.Row{
							severityText(f.Severity),
							f.Detector,
							f.Path,
							match,
						}
					}
					m.table.SetRows(rows)
					m.updateViewportContent()

					timeout := time.Now().Add(5 * time.Second)
					m.statusTimeout = &timeout
					m.statusMessage = fmt.Sprintf("Loaded historical scan from %s", selected.Timestamp.Format("Jan 2, 15:04"))
				}
			case "d", "x", "backspace", "delete":
				if m.historySelection >= 0 && m.historySelection < len(m.scanHistory) {
					auditLog := audit.NewAuditLog(".")
					if err := auditLog.DeleteRecord(m.historySelection); err == nil {
						if history, err := auditLog.LoadHistory(); err == nil {
							m.scanHistory = history
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

		if m.showClearConfirm {
			switch msg.String() {
			case "y", "Y":
				if m.clearConfirmStage == 1 {
					// First confirmation received, show second
					m.clearConfirmStage = 2
					return m, nil
				} else if m.clearConfirmStage == 2 {
					// Second confirmation received, delete files
					m.showClearConfirm = false
					m.clearConfirmStage = 0
					return m, m.clearHistory()
				}
			case "n", "N", "esc", "q":
				m.showClearConfirm = false
				m.clearConfirmStage = 0
				timeout := time.Now().Add(3 * time.Second)
				m.statusTimeout = &timeout
				m.statusMessage = "Clear history canceled"
				return m, nil
			}
			return m, nil
		}

		if m.searchMode {
			switch msg.String() {
			case "enter":
				m.searchQuery = m.searchInput.Value()
				m.searchMode = false
				m.searchInput.Blur()
				return m, nil
			case "esc":
				m.searchMode = false
				m.searchInput.Blur()
				m.searchInput.SetValue(m.searchQuery)
				m.applyFilters()
				return m, nil
			default:
				m.searchInput, cmd = m.searchInput.Update(msg)
				m.searchQuery = m.searchInput.Value()
				m.applyFilters()
				return m, cmd
			}
		}

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
			case "g": // gg - go to top
				if !m.showEmpty {
					m.table.GotoTop()
					m.updateViewportContent()
				}
				return m, nil
			default:
				return m, nil
			}
		}

		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "/":
			if !m.showEmpty || len(m.findings) > 0 {
				m.searchMode = true
				m.searchInput.SetValue(m.searchQuery)
				m.searchInput.Focus()
				return m, textinput.Blink
			}
		case "1":
			m.severityFilter = types.SevHigh
			m.applyFilters()
			timeout := time.Now().Add(3 * time.Second)
			m.statusTimeout = &timeout
			m.statusMessage = "Showing HIGH severity only (Esc to clear)"
			return m, nil
		case "2":
			m.severityFilter = types.SevMed
			m.applyFilters()
			timeout := time.Now().Add(3 * time.Second)
			m.statusTimeout = &timeout
			m.statusMessage = "Showing MED severity only (Esc to clear)"
			return m, nil
		case "3":
			m.severityFilter = types.SevLow
			m.applyFilters()
			timeout := time.Now().Add(3 * time.Second)
			m.statusTimeout = &timeout
			m.statusMessage = "Showing LOW severity only (Esc to clear)"
			return m, nil
		case "esc":
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
		case "n": // next HIGH
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
		case "N": // prev HIGH
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
		case "s":
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
		case "S":
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
		case "v": // toggle selection
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
		case "V": // select all
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
		case "B":
			if len(m.selectedFindings) > 0 {
				cmd := m.bulkBaseline()
				m.rebuildTableRows()
				return m, cmd
			}
			timeout := time.Now().Add(2 * time.Second)
			m.statusTimeout = &timeout
			m.statusMessage = "No findings selected (press v to select)"
			return m, nil
		case "ctrl+i": // bulk ignore
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
		case "I": // unignore
			if !m.showEmpty {
				return m, m.unignoreFile()
			}
		case "b":
			if !m.showEmpty {
				return m, m.addToBaseline()
			}
		case "U": // unbaseline
			if !m.showEmpty {
				return m, m.removeFromBaseline()
			}
		case "e": // export
			if len(m.getDisplayFindings()) > 0 {
				m.showExportMenu = true
				return m, nil
			}
		case "+", "=":
			if !m.showEmpty {
				m.expandContext()
				timeout := time.Now().Add(2 * time.Second)
				m.statusTimeout = &timeout
				m.statusMessage = fmt.Sprintf("Context: %d lines", m.contextLines*2+1)
				return m, nil
			}
		case "-", "_":
			if !m.showEmpty {
				m.contractContext()
				timeout := time.Now().Add(2 * time.Second)
				m.statusTimeout = &timeout
				m.statusMessage = fmt.Sprintf("Context: %d lines", m.contextLines*2+1)
				return m, nil
			}
		case "*": // toggle hide secrets
			m.hideSecrets = !m.hideSecrets
			// Persist preference
			prefs := Prefs{HideSecrets: m.hideSecrets}
			_ = SavePrefs(prefs) //nolint:errcheck // Best effort save, don't fail TUI
			m.rebuildTableRows()
			timeout := time.Now().Add(3 * time.Second)
			m.statusTimeout = &timeout
			if m.hideSecrets {
				m.statusMessage = "Secrets hidden (*: show)"
			} else {
				m.statusMessage = "Secrets visible (*: hide)"
			}
			return m, nil
		case "y": // copy path
			if !m.showEmpty {
				return m, m.copyPathToClipboard()
			}
		case "Y": // copy finding
			if !m.showEmpty {
				return m, m.copyFindingToClipboard()
			}
		case "D": // diff mode
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
		case "tab":
			if m.groupMode != GroupNone {
				m.toggleGroupExpansion()
				return m, nil
			}
		case "r":
			if m.rescanFunc == nil {
				timeout := time.Now().Add(3 * time.Second)
				m.statusTimeout = &timeout
				m.statusMessage = "Rescan not available"
				return m, nil
			}
			if !m.scanning {
				m.scanning = true
				m.hasScannedOnce = true
				scanMsg := "Scanning..."
				if m.hasScannedOnce {
					scanMsg = "Rescanning..."
				}
				m.statusMessage = scanMsg
				return m, m.rescan()
			}
		case "a": // history
			if !m.showScanHistory {
				auditLog := audit.NewAuditLog(".")
				history, err := auditLog.LoadHistory()
				if err == nil {
					m.scanHistory = history
					m.historySelection = 0
				}
			}
			m.showScanHistory = !m.showScanHistory
		case "X": // clear history (requires double confirmation)
			m.showClearConfirm = true
			m.clearConfirmStage = 1
			return m, nil
		case "?", "h":
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
		case "ctrl+d":
			if !m.showEmpty {
				halfPage := m.table.Height() / 2
				if halfPage < 1 {
					halfPage = 1
				}
				m.table.MoveDown(halfPage)
				m.updateViewportContent()
				return m, nil
			}
		case "ctrl+u":
			if !m.showEmpty {
				halfPage := m.table.Height() / 2
				if halfPage < 1 {
					halfPage = 1
				}
				m.table.MoveUp(halfPage)
				m.updateViewportContent()
				return m, nil
			}
		case "ctrl+f", "pgdown":
			if !m.showEmpty {
				m.table.MoveDown(m.table.Height())
				m.updateViewportContent()
				return m, nil
			}
		case "ctrl+b", "pgup":
			if !m.showEmpty {
				m.table.MoveUp(m.table.Height())
				m.updateViewportContent()
				return m, nil
			}
		case "g":
			m.pendingKey = "g"
			return m, nil
		case "home":
			if !m.showEmpty {
				m.table.GotoTop()
				m.updateViewportContent()
				return m, nil
			}
		case "G", "end":
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

		usableWidth := m.width - 10
		sevWidth := 8
		detectorWidth := 20
		remainingWidth := usableWidth - sevWidth - detectorWidth
		pathWidth := int(float64(remainingWidth) * 0.45)
		matchWidth := remainingWidth - pathWidth
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

		statsHeaderHeight := 1
		availableHeight := m.height - lipgloss.Height(statusStyle.Render("")) - statsHeaderHeight
		tableHeight := int(float64(availableHeight) * 0.45)
		viewportHeight := availableHeight - tableHeight - detailPaneBorderStyle.GetVerticalFrameSize() - 1

		m.table.SetWidth(m.width)
		m.table.SetHeight(tableHeight)

		if m.viewport.Height == 0 {
			m.viewport = viewport.New(m.width, viewportHeight)
		} else {
			m.viewport.Width = m.width
			m.viewport.Height = viewportHeight
		}
		m.updateViewportContent()
		statusStyle = statusStyle.Width(m.width)

		// Update legend with new width (only if no temporary message)
		if m.statusTimeout == nil {
			m.statusMessage = buildLegend(m.width, m.showEmpty, m.hideSecrets)
		}

	case findingsMsg:
		m.findings = msg
		m.showEmpty = len(m.findings) == 0
		m.lastScanTime = time.Now()
		m.viewingCached = false

		rows := make([]table.Row, len(m.findings))
		for i, f := range m.findings {
			match := f.Match
			if m.hideSecrets {
				match = redactSecret(match)
			}
			rows[i] = table.Row{
				severityText(f.Severity),
				f.Detector,
				f.Path,
				match,
			}
		}
		m.table.SetRows(rows)
		if m.showEmpty {
			m.table.SetCursor(0)
		}
		m.updateViewportContent()

		m.scanning = false
		m.hasScannedOnce = true
		timeout := time.Now().Add(5 * time.Second)
		m.statusTimeout = &timeout
		if m.showEmpty {
			m.statusMessage = "Rescan complete - no new secrets found"
		} else {
			m.statusMessage = fmt.Sprintf("Rescan complete - found %d findings", len(m.findings))
		}

	case statusMsg:
		timeout := time.Now().Add(3 * time.Second)
		m.statusTimeout = &timeout
		m.statusMessage = string(msg)

	case spinner.TickMsg:
		var spinCmd tea.Cmd
		m.spinner, spinCmd = m.spinner.Update(msg)
		if m.statusTimeout != nil && time.Now().After(*m.statusTimeout) {
			m.statusTimeout = nil
			m.statusMessage = buildLegend(m.width, m.showEmpty, m.hideSecrets)
		}
		return m, spinCmd
	}

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

	m.updateViewportContent()
	return m, cmd
}

func (m Model) View() string {
	if m.quitting {
		return ""
	}
	if !m.ready {
		return "Initializing..."
	}

	if m.scanning {
		scanType := "Scanning"
		if m.hasScannedOnce {
			scanType = "Rescanning"
		}
		msgContent := fmt.Sprintf("%s  %s...\n\nPlease wait", m.spinner.View(), scanType)
		popupBox := popupStyle.
			Width(55).
			Align(lipgloss.Center).
			Render(msgContent)
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, popupBox)
	}

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

	var statsContent string
	if len(m.findings) == 0 {
		if m.viewingCached {
			statsContent = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Render("[OK] All findings baselined")
		} else {
			statsContent = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Render("[OK] No secrets detected")
		}
	} else {
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

		sortInfo := m.getSortIndicator()
		var selectionInfo string
		if len(m.selectedFindings) > 0 {
			selectionInfo = fmt.Sprintf("  [%d selected]", len(m.selectedFindings))
		}
		var hideSecretsIndicator string
		if m.hideSecrets {
			hideSecretsIndicator = "  [SECRETS HIDDEN]"
		}

		if m.filteredFindings != nil {
			statsContent = fmt.Sprintf(
				"Showing: %d/%d  |  %s %-4d  |  %s %-4d  |  %s %-4d%s%s%s%s",
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
				hideSecretsIndicator,
			)
		} else {
			statsContent = fmt.Sprintf(
				"Total: %-4d  |  %s %-4d  |  %s %-4d  |  %s %-4d%s%s%s",
				len(m.findings),
				sevHighStyle.Render("High:"),
				highCount,
				sevMedStyle.Render("Med:"),
				medCount,
				sevLowStyle.Render("Low:"),
				lowCount,
				sortInfo,
				selectionInfo,
				hideSecretsIndicator,
			)
		}
	}

	statsHeader := lipgloss.NewStyle().
		Width(m.width).
		Padding(0, 2).
		Foreground(lipgloss.Color("15")).
		Background(lipgloss.Color("237")).
		Render(statsContent)

	tableRender := tableBorderStyle.
		Width(m.width).
		Height(m.table.Height()).
		Render(m.table.View())

	var detailContent string
	if len(displayFindings) == 0 {
		var emptyMsg string
		if len(m.findings) == 0 {
			emptyMsg = "No secrets to review.\n\nPress 'r' to rescan\nPress '?' for help"
		} else {
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

	var timeInfo string
	if m.viewingHistorical {
		timeInfo = fmt.Sprintf("Viewing: %s", m.lastScanTime.Format("Jan 2, 15:04"))
	} else if !m.lastScanTime.IsZero() {
		timeAgo := time.Since(m.lastScanTime)
		timeInfo = fmt.Sprintf("Scanned: %s ago", formatDuration(timeAgo))
	}

	statusLeft := m.statusMessage
	statusRight := timeInfo
	leftWidth := lipgloss.Width(statusLeft)
	rightWidth := lipgloss.Width(statusRight)
	availWidth := m.width - 4
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

	var bottomBar string
	if m.searchMode {
		matchCount := len(m.getDisplayFindings())
		searchStatus := fmt.Sprintf(" (%d matches)", matchCount)
		searchBarStyle := lipgloss.NewStyle().
			Background(lipgloss.Color("235")).
			Foreground(lipgloss.Color("15")).
			Width(m.width).
			Padding(0, 1)
		bottomBar = searchBarStyle.Render(m.searchInput.View() + searchStatus)
	} else {
		bottomBar = statusRender
	}

	mainView := lipgloss.JoinVertical(lipgloss.Left,
		statsHeader,
		tableRender,
		detailRender,
		bottomBar,
	)

	if m.showHelp {
		titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15"))
		sepStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))

		// Build a row with consistent blue background
		rowBg := lipgloss.Color("235") // match popup background
		keyOnBg := lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Background(rowBg)
		descOnBg := lipgloss.NewStyle().Foreground(lipgloss.Color("250")).Background(rowBg)
		rowStyle := lipgloss.NewStyle().Background(rowBg)

		row := func(k1, d1, k2, d2 string) string {
			result := keyOnBg.Render(fmt.Sprintf("%-6s", k1)) +
				descOnBg.Render(fmt.Sprintf("%-14s", d1)) +
				rowStyle.Render("  ") +
				keyOnBg.Render(fmt.Sprintf("%-6s", k2)) +
				descOnBg.Render(fmt.Sprintf("%-14s", d2))
			return result
		}

		var lines []string
		lines = append(lines, titleStyle.Render("Keyboard Shortcuts"))
		lines = append(lines, "")
		lines = append(lines, row("j/k", "Navigate", "g/G", "Top/bottom"))
		lines = append(lines, row("n/N", "Next/prev HIGH", "^d/u", "Half-page"))
		lines = append(lines, sepStyle.Render(strings.Repeat("─", 42)))
		lines = append(lines, row("/", "Search", "Esc", "Clear filter"))
		lines = append(lines, row("1/2/3", "HIGH/MED/LOW", "s/S", "Sort"))
		lines = append(lines, sepStyle.Render(strings.Repeat("─", 42)))
		lines = append(lines, row("Enter", "Open in editor", "r", "Rescan"))
		lines = append(lines, row("i/I", "Ignore file", "b/U", "Baseline"))
		lines = append(lines, row("v/V", "Select", "B", "Bulk baseline"))
		lines = append(lines, sepStyle.Render(strings.Repeat("─", 42)))
		lines = append(lines, row("e", "Export", "y/Y", "Copy path"))
		lines = append(lines, row("+/-", "Expand context", "gf", "Group by file"))
		lines = append(lines, row("D", "Diff view", "a", "Audit log"))
		lines = append(lines, sepStyle.Render(strings.Repeat("─", 42)))
		lines = append(lines, row("*", "Hide secrets", "X", "Clear history"))
		lines = append(lines, row("?", "This help", "q", "Quit"))
		lines = append(lines, "")
		lines = append(lines, sepStyle.Italic(true).Render("Press any key to close"))

		helpContent := lipgloss.JoinVertical(lipgloss.Left, lines...)
		helpBox := popupStyle.Width(48).Padding(1, 2).Render(helpContent)
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, helpBox)
	}

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

	if m.showClearConfirm {
		titleStyle := lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("15"))

		warningStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("9")).
			Bold(true)

		var lines []string
		if m.clearConfirmStage == 1 {
			lines = append(lines, titleStyle.Render("Clear Scan History?"))
			lines = append(lines, "")
			lines = append(lines, "This will delete:")
			lines = append(lines, "  - .redactyl_audit.jsonl (audit log)")
			lines = append(lines, "  - .redactyl_last_scan.json (scan cache)")
			lines = append(lines, "")
			lines = append(lines, warningStyle.Render("This cannot be undone."))
			lines = append(lines, "")
			lines = append(lines, "Press Y to continue, N to cancel")
		} else if m.clearConfirmStage == 2 {
			lines = append(lines, warningStyle.Render("ARE YOU SURE?"))
			lines = append(lines, "")
			lines = append(lines, "Press Y again to confirm deletion")
			lines = append(lines, "Press N to cancel")
		}

		confirmContent := lipgloss.JoinVertical(lipgloss.Left, lines...)
		confirmBox := popupStyle.
			Width(45).
			Padding(1, 3).
			Render(confirmContent)

		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, confirmBox)
	}

	if m.diffMode {
		titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15"))
		newStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
		fixedStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)
		dimStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))

		var lines []string
		lines = append(lines, titleStyle.Render(fmt.Sprintf("DIFF: %s vs Current",
			m.diffPrevTimestamp.Format("Jan 2, 15:04"))))
		lines = append(lines, "")

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

	if m.showScanHistory {
		titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Render("SCAN HISTORY")
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

			maxScans := 10
			if len(history) < maxScans {
				maxScans = len(history)
			}

			for i := 0; i < maxScans; i++ {
				scan := history[i]
				timeStr := scan.Timestamp.Format("Jan 2, 15:04:05")

				summaryStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("7"))
				if scan.TotalFindings == 0 {
					summaryStyle = summaryStyle.Foreground(lipgloss.Color("10"))
				} else if scan.NewFindings > 0 {
					summaryStyle = summaryStyle.Foreground(lipgloss.Color("11"))
				}

				summary := fmt.Sprintf("%s - %d findings (%d new, %d baselined)",
					timeStr, scan.TotalFindings, scan.NewFindings, scan.BaselinedCount)

				if i == m.historySelection {
					lines = append(lines, lipgloss.NewStyle().
						Foreground(lipgloss.Color("232")).
						Background(lipgloss.Color("208")).
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

		historyBox := popupStyle.Width(70).Padding(2, 4).Render(content)
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, historyBox)
	}

	return mainView
}

// buildLegend creates a responsive legend bar that adapts to terminal width.
// Items are added in priority order until width is exhausted.
func buildLegend(width int, showEmpty bool, hideSecrets bool) string {
	if showEmpty {
		return "q: quit | r: rescan | a: audit log"
	}

	// Show action that will happen when pressed
	secretsLabel := "*: show"
	if !hideSecrets {
		secretsLabel = "*: hide"
	}

	// Legend items in priority order (most important first)
	items := []string{
		"q: quit",
		"?: help",
		"j/k: nav",
		"i: ignore",
		"b: baseline",
		"r: rescan",
		secretsLabel,
		"a: audit",
	}

	separator := " | "
	sepLen := len(separator)
	available := width - 4 // padding

	var result []string
	usedWidth := 0

	for _, item := range items {
		itemLen := len(item)
		needed := itemLen
		if len(result) > 0 {
			needed += sepLen
		}

		if usedWidth+needed <= available {
			result = append(result, item)
			usedWidth += needed
		}
	}

	return strings.Join(result, separator)
}
