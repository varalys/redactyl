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
| `n` / `N` | Jump to next / previous HIGH finding |

### Search & Filter
| Key | Action |
|-----|--------|
| `/` | Search findings by path, detector, or match text |
| `1` / `2` / `3` | Filter by HIGH / MED / LOW severity |
| `s` | Sort: cycle through severity, path, detector |
| `S` | Reverse current sort order |
| `Esc` | Clear all filters |

### Selection & Bulk Operations
| Key | Action |
|-----|--------|
| `v` | Toggle selection on current finding |
| `V` | Select / deselect all visible findings |
| `B` | Bulk baseline all selected findings |
| `Ctrl+i` | Bulk ignore all selected files |

### Export & Clipboard
| Key | Action |
|-----|--------|
| `e` | Export current view (JSON/CSV/SARIF) |
| `y` | Copy file path to clipboard |
| `Y` | Copy full finding details to clipboard |

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

### Diff View (press `D`)
| Key | Action |
|-----|--------|
| `D` | Compare current scan vs previous scan |
| `D` / `Esc` | Close diff view |

Shows new findings (red, +) and fixed findings (green, -) since last scan.

### Context Expansion
| Key | Action |
|-----|--------|
| `+` / `=` | Show more context lines around finding |
| `-` / `_` | Show fewer context lines around finding |

Context view shows line numbers and highlights the finding line. Git commit info (hash, author, date) is displayed when available.

### Grouping
| Key | Action |
|-----|--------|
| `gf` | Group findings by file path |
| `gd` | Group findings by detector type |
| `Tab` | Expand / collapse current group |
| `gg` | Go to first row (vim style) |

Groups show a count of findings and can be expanded/collapsed. Press `gf` or `gd` again to disable grouping.

### Virtual File Handling
For findings inside archives or containers (paths containing `::`):
- Detail pane shows "VIRTUAL FILE" warning in yellow
- Archive/Layer/File breakdown is displayed
- Pressing `o` to open shows "Cannot open virtual file" message
- Git blame is skipped for virtual files

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

All phases complete! Future enhancements could include:
- Extract virtual files to temp and open
- Syntax highlighting in context preview
- More export formats

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
