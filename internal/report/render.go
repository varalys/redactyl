package report

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"time"

	"github.com/franzer/redactyl/internal/types"
	"github.com/olekukonko/tablewriter"
)

// PrintOptions controls table rendering and summary stats for PrintTable.
type PrintOptions struct {
	NoColor       bool
	Duration      time.Duration
	FilesScanned  int
	TotalFiles    int // Total files that could be scanned
	TotalFindings int // Total findings before baseline filtering
}

// PrintText renders findings as columnar text output and emits a
// summary footer containing counts and optional duration/files scanned.
func PrintText(w io.Writer, findings []types.Finding, opts PrintOptions) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Path == findings[j].Path {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].Path < findings[j].Path
	})
	if len(findings) == 0 {
		fmt.Fprintln(w, "No secrets found ✅")
	} else {
		// Column widths
		maxDet := 8
		for _, f := range findings {
			if l := len(f.Detector); l > maxDet {
				maxDet = l
			}
		}
		// Header and rows
		fmt.Fprintf(w, "Findings: %d\n", len(findings))
		for _, f := range findings {
			sev := string(f.Severity)
			if !opts.NoColor {
				sev = colorSeverity(f.Severity)
			}
			mask := maskValue(f.Match)
			fmt.Fprintf(w, "%-6s %-*s %s:%d  %s\n", sev, maxDet, f.Detector, f.Path, f.Line, mask)
		}
	}
	// Summary footer
	high, med, low := 0, 0, 0
	for _, f := range findings {
		switch f.Severity {
		case types.SevHigh:
			high++
		case types.SevMed:
			med++
		default:
			low++
		}
	}
	// Summary footer (always show if we have stats)
	if opts.Duration > 0 || opts.FilesScanned > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Findings: %d (high: %d, medium: %d, low: %d)\n", len(findings), high, med, low)

		// Show cache transparency info
		if opts.TotalFindings > 0 && opts.TotalFindings > len(findings) {
			cached := opts.TotalFindings - len(findings)
			fmt.Fprintf(w, "Previously found (cached): %d\n", cached)
		}
		if opts.TotalFiles > 0 && opts.TotalFiles > opts.FilesScanned {
			skipped := opts.TotalFiles - opts.FilesScanned
			fmt.Fprintf(w, "Files skipped (cached): %d\n", skipped)
		}

		if opts.Duration > 0 {
			fmt.Fprintf(w, "Scan duration: %.2fs\n", opts.Duration.Seconds())
		}
		if opts.FilesScanned > 0 {
			fmt.Fprintf(w, "Files scanned: %d\n", opts.FilesScanned)
		}
	}
}

func maskValue(s string) string {
	if len(s) <= 8 {
		return "********"
	}
	return s[:4] + "…" + s[len(s)-4:]
}

func colorSeverity(s types.Severity) string {
	switch s {
	case types.SevHigh:
		return "\x1b[31mhigh\x1b[0m" // red
	case types.SevMed:
		return "\x1b[33mmedium\x1b[0m" // yellow
	default:
		return "\x1b[36mlow\x1b[0m" // cyan
	}
}

// PrintTable renders findings as a formatted table using tablewriter and emits a
// summary footer containing counts and optional duration/files scanned.
func PrintTable(w io.Writer, findings []types.Finding, opts PrintOptions) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Path == findings[j].Path {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].Path < findings[j].Path
	})

	if len(findings) == 0 {
		fmt.Fprintln(w, "No secrets found ✅")
	} else {
		table := tablewriter.NewWriter(w)
		table.Header("Severity", "Detector", "File", "Line", "Match")

		// Add findings to table
		for _, f := range findings {
			sev := string(f.Severity)
			if !opts.NoColor {
				sev = colorSeverity(f.Severity)
			}
			mask := maskValue(f.Match)
			_ = table.Append(
				sev,
				f.Detector,
				f.Path,
				strconv.Itoa(f.Line),
				mask,
			)
		}
		_ = table.Render()
	}

	// Summary footer (same as PrintText)
	high, med, low := 0, 0, 0
	for _, f := range findings {
		switch f.Severity {
		case types.SevHigh:
			high++
		case types.SevMed:
			med++
		default:
			low++
		}
	}

	// Summary footer (always show if we have stats)
	if opts.Duration > 0 || opts.FilesScanned > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Findings: %d (high: %d, medium: %d, low: %d)\n", len(findings), high, med, low)

		// Show cache transparency info
		if opts.TotalFindings > 0 && opts.TotalFindings > len(findings) {
			cached := opts.TotalFindings - len(findings)
			fmt.Fprintf(w, "Previously found (cached): %d\n", cached)
		}
		if opts.TotalFiles > 0 && opts.TotalFiles > opts.FilesScanned {
			skipped := opts.TotalFiles - opts.FilesScanned
			fmt.Fprintf(w, "Files skipped (cached): %d\n", skipped)
		}

		if opts.Duration > 0 {
			fmt.Fprintf(w, "Scan duration: %.2fs\n", opts.Duration.Seconds())
		}
		if opts.FilesScanned > 0 {
			fmt.Fprintf(w, "Files scanned: %d\n", opts.FilesScanned)
		}
	}
}
