package report

import (
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/redactyl/redactyl/internal/types"
)

type PrintOptions struct {
	NoColor      bool
	Duration     time.Duration
	FilesScanned int
}

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
