# Redactyl TUI Implementation Plan

**Goal:** Create an interactive Terminal User Interface (TUI) for reviewing, filtering, and remediating scan results.

**Target Version:** v1.1 or v1.2
**Tech Stack:** [Bubble Tea](https://github.com/charmbracelet/bubbletea), [Bubbles](https://github.com/charmbracelet/bubbles), [Lip Gloss](https://github.com/charmbracelet/lipgloss) (styling).

## Core Features

1.  **Interactive Results List**
    - Scrollable list of findings.
    - Columns: Severity (colored icon), Detector, File Path, Secret Snippet (redacted/masked).
    - Keyboard navigation (j/k/arrows).

2.  **Detail / Context Pane**
    - Split view (List on left/top, Details on right/bottom).
    - Show full context lines around the finding.
    - Syntax highlighting (if possible/easy) or simple color highlighting of the match.
    - Metadata display (Commit ID, Author, Timestamp for git history findings).

3.  **Action Workflow (Triage)**
    - **Ignore (`i`):** Add the file/path to `.redactylignore`.
    - **Baseline (`b`):** Mark this specific finding as "accepted" (add to baseline).
    - **Open (`o` / `Enter`):** Open the file in the user's `$EDITOR` at the correct line number.
    - **False Positive (`f`):** (Optional) Tag as false positive for feedback loop.

## Implementation Steps

### Phase 1: Setup & Basic List
1.  [ ] Add dependencies: `go get github.com/charmbracelet/bubbletea github.com/charmbracelet/bubbles github.com/charmbracelet/lipgloss`.
2.  [ ] Create `internal/tui` package.
3.  [ ] Define the `Model` struct:
    ```go
    type Model struct {
        findings []core.Finding
        cursor   int
        width    int
        height   int
        // ... bubbles components
    }
    ```
4.  [ ] Implement `Init`, `Update`, `View`.
5.  [ ] Add `redactyl scan --interactive` (or `-i`) flag to trigger the TUI instead of text output.

### Phase 2: Detail View & Styling
1.  [ ] Use `lipgloss` to create a split-pane layout.
2.  [ ] Render the `Context` field from the finding in the detail pane.
3.  [ ] Highlight the `Match` string within the context.
4.  [ ] Add status bar (e.g., "Finding 5 of 102 | q: Quit | i: Ignore").

### Phase 3: Actions (The "Huge Win")
1.  [ ] **Open Editor:** Implement logic to look up `$EDITOR` (or default to `vim`/`nano`) and `exec.Command` it.
    - *Challenge:* Opening editor pauses the TUI. Bubble Tea handles this via `tea.Exec`.
2.  [ ] **Ignore File:** Implement logic to append entry to `.redactylignore`.
    - *UX:* Show a confirmation or ephemeral "Toast" message ("Added .env to ignore").
3.  [ ] **Update Baseline:** Implement logic to add finding to `redactyl.baseline.json` (reuse existing baseline logic).

### Phase 4: Polish
1.  [ ] **Filtering:** Allow typing `/` to filter list by filename or rule ID.
2.  [ ] **Artifact Support:** Handle "virtual paths" gracefully (e.g., can't open `image.tar::layer::file` in `$EDITOR` easily—maybe just show a "Cannot open virtual file" message or extract it to temp).
3.  [ ] **Help:** Press `?` to show keybindings.

## Architecture Note
The TUI should sit in `internal/tui` and be called by `cmd/redactyl/scan.go` when the `--interactive` flag is present. It will take `[]core.Finding` as input, similar to how the JSON reporter works.
