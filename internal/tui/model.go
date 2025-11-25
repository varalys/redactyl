package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	"github.com/charmbracelet/bubbletea"
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
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	} else if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	} else if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	} else {
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// Model represents the main state of the TUI application.
type Model struct {
	table            table.Model
	viewport         viewport.Model
	spinner          spinner.Model
	findings         []types.Finding
	baselinedSet     map[string]bool                 // Keys of baselined findings
	quitting         bool
	ready            bool       // Indicates if terminal dimensions are known
	scanning         bool       // True when rescan is in progress
	hasScannedOnce   bool       // True after first scan completes
	initialScanDone  bool       // True if we started with findings (not first ever scan)
	viewingCached      bool       // True when viewing cached results
	cachedTimestamp    time.Time  // Timestamp of cached results
	lastScanTime       time.Time  // Timestamp of the last scan (always set)
	viewingHistorical  bool       // True when viewing a historical scan from audit log
	showScanHistory    bool       // True when scan history popup is shown
	scanHistory        []audit.ScanRecord // Loaded scan history
	historySelection   int        // Selected scan in history list (0-based)
	height           int
	width            int
	statusMessage    string
	statusTimeout    *time.Time                      // When to clear status message
	rescanFunc       func() ([]types.Finding, error) // Callback to re-run scan
	showEmpty        bool                            // True if no findings were found
	showHelp         bool                            // True when help overlay is shown
}

// NewModel initializes a new TUI model.
func NewModel(findings []types.Finding, rescanFunc func() ([]types.Finding, error)) Model {
	// Define table columns - use plain text (no ANSI) to avoid truncation issues
	columns := []table.Column{
		{Title: "Sev", Width: 8},   // "HIGH" or "(b) HIGH"
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

	// Initialize main model
	m := Model{
		table:           t,
		spinner:         sp,
		findings:        findings,
		rescanFunc:      rescanFunc,
		showEmpty:       len(findings) == 0,
		initialScanDone: len(findings) > 0, // If we have findings, this wasn't the first ever scan
		hasScannedOnce:  true,              // We've already completed the initial scan to get here
		lastScanTime:    time.Now(),        // Set scan time to now
	}

	if m.showEmpty {
		m.statusMessage = "q: quit | r: rescan | a: audit log"
	} else {
		m.statusMessage = "q: quit | ?: help | j/k: navigate | o: open | i: ignore | b: baseline | a: audit log"
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

// updateViewportContent updates the detail view with the currently selected finding.
func (m *Model) updateViewportContent() {
	if len(m.findings) == 0 || !m.ready {
		m.viewport.SetContent("")
		return
	}

	idx := m.table.Cursor()
	if idx >= 0 && idx < len(m.findings) {
		f := m.findings[idx]

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

		// Render finding details using keyStyle for labels
		b.WriteString(fmt.Sprintf("%s %s\n", keyStyle.Render("Path:"), f.Path))
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

		b.WriteString(fmt.Sprintf("\n%s\n", keyStyle.Render("Context:")))

		context := f.Context
		if context == "" {
			context = f.Match // Fallback to match if no context
		}

		// Highlight the matched string within the context
		if f.Match != "" {
			context = strings.ReplaceAll(context, f.Match, matchStyle.Render(f.Match))
		}
		b.WriteString(context)

		m.viewport.SetContent(b.String())
	}
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

		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
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
		case "r": // Rescan key
			if m.viewingCached {
				// In cached mode, show error message
				timeout := time.Now().Add(3 * time.Second)
				m.statusTimeout = &timeout
				m.statusMessage = "Rescan not available - exit and run 'redactyl scan -i' to rescan"
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
		case "g", "home": // Jump to top of table
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
		m.viewingCached = false      // No longer viewing cached results after rescan

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
		m.scanning = false   // Scan complete
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
				m.statusMessage = "q: quit | ?: help | j/k: navigate | o: open | i: ignore | b: baseline"
			}
		}
		return m, spinCmd
	}

	// Update table (for navigation not handled by custom keybindings)
	if !m.quitting && !m.showEmpty {
		if _, ok := msg.(tea.KeyMsg); !ok || (msg.(tea.KeyMsg).String() != "down" && msg.(tea.KeyMsg).String() != "j" && msg.(tea.KeyMsg).String() != "up" && msg.(tea.KeyMsg).String() != "k") {
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

	// Calculate stats
	var highCount, medCount, lowCount int
	for _, f := range m.findings {
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
		// Show counts
		statsContent = fmt.Sprintf(
			"Total: %-4d  |  %s %-4d  |  %s %-4d  |  %s %-4d",
			len(m.findings),
			sevHighStyle.Render("High:"),
			highCount,
			sevMedStyle.Render("Med:"),
			medCount,
			sevLowStyle.Render("Low:"),
			lowCount,
		)
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

	// Detail pane - show message if no findings
	var detailContent string
	if len(m.findings) == 0 {
		emptyMsg := "No secrets to review.\n\nPress 'r' to rescan\nPress '?' for help"
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

	mainView := lipgloss.JoinVertical(lipgloss.Left,
		statsHeader,
		tableRender,
		detailRender,
		statusRender,
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
		lines = append(lines, "")

		// Actions
		lines = append(lines, sectionStyle.Render("Actions"))
		lines = append(lines, formatRow("Enter", "Open in $EDITOR"))
		lines = append(lines, formatRow("i / I", "Ignore / unignore file"))
		lines = append(lines, formatRow("b / U", "Baseline / unbaseline"))
		lines = append(lines, formatRow("r", "Rescan"))
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
