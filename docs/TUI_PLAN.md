# Redactyl TUI

Interactive Terminal User Interface for reviewing, filtering, and remediating scan results.

**Tech Stack:** [Bubble Tea](https://github.com/charmbracelet/bubbletea), [Bubbles](https://github.com/charmbracelet/bubbles), [Lip Gloss](https://github.com/charmbracelet/lipgloss)

## Current Features (Implemented)

### Navigation
| Key | Action |
|-----|--------|
| `j` / `k` | Move down / up one row |
| `Ctrl+d` / `Ctrl+u` | Half-page down / up |
| `Ctrl+f` / `Ctrl+b` | Full page down / up |
| `g` / `G` | Jump to first / last row |
| `PgUp` / `PgDown` | Full page up / down |
| `Home` / `End` | Jump to first / last row |

### Actions
| Key | Action |
|-----|--------|
| `Enter` / `o` | Open file in `$EDITOR` at line |
| `i` | Add file to `.redactylignore` |
| `I` | Remove file from `.redactylignore` |
| `b` | Add finding to baseline |
| `U` | Remove finding from baseline |
| `r` | Rescan (fresh scan, ignores cache) |
| `a` | View scan history |
| `?` / `h` | Toggle help screen |
| `q` / `Ctrl+c` | Quit |

### Scan History (press `a`)
| Key | Action |
|-----|--------|
| `j` / `k` | Navigate history |
| `Enter` | Load selected historical scan |
| `d` / `x` | Delete selected scan entry |
| `a` / `Esc` | Close history popup |

### UI Components
- **Table View**: Findings list with severity, detector, path, match columns
- **Detail Pane**: Full finding info (path, detector, severity, line, column, secret, metadata, context)
- **Stats Header**: Total count and breakdown by severity (High/Med/Low)
- **Status Bar**: Keyboard hints + scan timestamp
- **Baseline Indicator**: `(b)` prefix and detail pane notice for baselined findings
- **Orange Selection**: Branded highlight color for selected rows

### Smart Features
- Auto-loads cached results when no new findings
- Audit log tracks all scans with full findings for historical review
- Editor integration with line/column positioning for VS Code, Vim, Emacs, Sublime, etc.

---

## Planned Features (TODO)

### Phase 5: Search & Filter
- [ ] **Search** (`/`): Filter findings by path, detector, or match text
- [ ] **Severity Filter** (`1`/`2`/`3`): Show only High/Med/Low findings
- [ ] **Jump to Severity** (`n`/`N`): Jump to next/previous HIGH finding
- [ ] **Clear Filter** (`Esc`): Reset to show all findings

### Phase 6: Sorting
- [ ] **Sort Toggle** (`s`): Cycle sort order (severity, path, detector)
- [ ] **Reverse Sort** (`S`): Reverse current sort order
- [ ] Visual indicator showing current sort column

### Phase 7: Bulk Operations
- [ ] **Select Mode** (`v`): Toggle selection on current finding
- [ ] **Select All** (`V`): Select/deselect all visible findings
- [ ] **Bulk Baseline** (`B`): Baseline all selected findings
- [ ] **Bulk Ignore** (`Ctrl+i`): Ignore all selected files
- [ ] Selection count in status bar

### Phase 8: Export & Clipboard
- [ ] **Export** (`e`): Export current view to JSON/SARIF/CSV
- [ ] **Copy Path** (`y`): Copy file path to clipboard
- [ ] **Copy Finding** (`Y`): Copy full finding details to clipboard

### Phase 9: Diff View
- [ ] **Diff Mode** (`D`): Compare current scan vs previous scan
- [ ] Show new findings (added since last scan)
- [ ] Show fixed findings (removed since last scan)
- [ ] Color coding: green for fixed, red for new

### Phase 10: Enhanced Context
- [ ] **Expand Context** (`+`/`-`): Show more/fewer lines around finding
- [ ] Syntax highlighting in context preview
- [ ] Git blame info (author, commit) for findings

### Phase 11: Grouping
- [ ] **Group by File** (`gf`): Collapse findings by file path
- [ ] **Group by Detector** (`gd`): Collapse findings by detector type
- [ ] **Expand/Collapse** (`Tab`): Toggle group expansion
- [ ] Group counts in collapsed view

### Phase 12: Virtual File Handling
- [ ] Detect virtual paths (e.g., `image.tar::layer::file`)
- [ ] Extract to temp and open option
- [ ] "Cannot open virtual file" graceful message
- [ ] Show container/archive context in detail pane

---

## Architecture

```
internal/tui/
├── model.go      # Main TUI model, state, Update/View logic
├── actions.go    # Action handlers (open, ignore, baseline, etc.)
├── run.go        # Entry points (Run, RunWithBaseline, RunCached)
└── *_test.go     # Tests
```

The TUI is invoked by `cmd/redactyl/scan.go` when running interactively (default for TTY). It receives `[]types.Finding` and optional baseline data.

## Design Principles

1. **Vim-first**: All navigation follows vim conventions
2. **Non-destructive**: Actions are reversible (unignore, unbaseline)
3. **Fast**: Cached results load instantly, full context available
4. **Accessible**: ASCII-only characters for terminal compatibility
5. **Branded**: Orange selection highlight for Redactyl identity
