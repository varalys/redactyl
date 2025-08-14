package detectors

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"

	"github.com/redactyl/redactyl/internal/types"
)

// Shared helper regexes for detectors that need generic token matching.
var (
	reGenericKey32to64 = regexp.MustCompile(`[A-Za-z0-9_-]{32,64}`)
	reSkKey            = regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,}\b`)
)

// findSimple scans line-by-line and emits a finding when the regex matches.
// It respects inline ignores of the form: "redactyl:ignore" combined with a
// substring of the detector ID (e.g., provider name) present on the same line.
func findSimple(path string, data []byte, re *regexp.Regexp, id string, sev types.Severity, conf float64) []types.Finding {
	var out []types.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	ignoreRegion := false
	skipNext := false
	for sc.Scan() {
		line++
		t := sc.Text()
		// Region markers
		if strings.Contains(t, "redactyl:ignore-start") || strings.Contains(t, "redactyl: ignore-start") {
			ignoreRegion = true
			continue
		}
		if strings.Contains(t, "redactyl:ignore-end") || strings.Contains(t, "redactyl: ignore-end") {
			ignoreRegion = false
			continue
		}
		if ignoreRegion {
			continue
		}
		// Next-line marker
		if strings.Contains(t, "redactyl:ignore-next-line") || strings.Contains(t, "redactyl: ignore-next-line") {
			skipNext = true
			continue
		}
		if skipNext {
			skipNext = false
			continue
		}
		// Legacy single-line ignore with provider substring heuristic
		if strings.Contains(t, "redactyl:ignore") && strings.Contains(strings.ToLower(t), strings.Split(id, "_")[0]) {
			continue
		}
		if m := re.FindString(t); m != "" {
			out = append(out, types.Finding{Path: path, Line: line, Match: m, Detector: id, Severity: sev, Confidence: conf})
		}
	}
	return out
}

// findWithContext emits a finding only when a context regex matches the line
// and a value regex also matches (to reduce false positives for generic keys).
// Inline ignores work the same as in findSimple.
func findWithContext(path string, data []byte, ctxRe, valueRe *regexp.Regexp, id string, sev types.Severity, conf float64) []types.Finding {
	var out []types.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	// Region/next-line state for inline suppressions
	ignoreRegion := false
	skipNext := false
	for sc.Scan() {
		line++
		t := sc.Text()
		// Handle region markers first
		if strings.Contains(t, "redactyl:ignore-start") || strings.Contains(t, "redactyl: ignore-start") {
			ignoreRegion = true
			continue
		}
		if strings.Contains(t, "redactyl:ignore-end") || strings.Contains(t, "redactyl: ignore-end") {
			ignoreRegion = false
			continue
		}
		if ignoreRegion {
			continue
		}
		// Handle next-line marker
		if strings.Contains(t, "redactyl:ignore-next-line") || strings.Contains(t, "redactyl: ignore-next-line") {
			skipNext = true
			continue
		}
		if skipNext {
			skipNext = false
			continue
		}
		// Legacy single-line ignore retains provider substring heuristic
		if strings.Contains(t, "redactyl:ignore") && strings.Contains(strings.ToLower(t), strings.Split(id, "_")[0]) {
			continue
		}
		if ctxRe.MatchString(t) {
			if m := valueRe.FindString(t); m != "" {
				out = append(out, types.Finding{Path: path, Line: line, Match: m, Detector: id, Severity: sev, Confidence: conf})
			}
		}
	}
	return out
}
