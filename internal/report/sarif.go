// internal/report/sarif.go
package report

import (
	"encoding/json"
	"io"
	"time"

	"github.com/franzer/redactyl/internal/types"
)

type sarif struct {
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules,omitempty"`
}

type sarifResult struct {
	RuleID    string       `json:"ruleId"`
	Level     string       `json:"level"`
	Message   sarifMessage `json:"message"`
	Locations []sarifLoc   `json:"locations"`
	RuleIndex int          `json:"ruleIndex,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLoc struct {
	PhysicalLocation sarifPhys `json:"physicalLocation"`
}

type sarifPhys struct {
	ArtifactLocation sarifArt    `json:"artifactLocation"`
	Region           sarifRegion `json:"region"`
}

type sarifArt struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int           `json:"startLine"`
	Snippet   *sarifSnippet `json:"snippet,omitempty"`
}

type sarifSnippet struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID           string        `json:"id"`
	ShortDesc    *sarifMessage `json:"shortDescription,omitempty"`
	Help         *sarifMessage `json:"help,omitempty"`
	DefaultLevel string        `json:"defaultConfiguration,omitempty"`
}

func sevToLevel(s types.Severity) string {
	switch s {
	case types.SevHigh:
		return "error"
	case types.SevMed:
		return "warning"
	default:
		return "note"
	}
}

// WriteSARIF writes findings as SARIF 2.1.0 to the provided writer.
func WriteSARIF(w io.Writer, findings []types.Finding) error {
	run := sarifRun{Tool: sarifTool{Driver: sarifDriver{Name: "redactyl", Version: time.Now().Format("2006.01.02")}}}
	// Build a stable set of rules under tool.driver.rules to reference by index
	ruleIndex := map[string]int{}
	for _, f := range findings {
		if _, ok := ruleIndex[f.Detector]; !ok {
			ruleIndex[f.Detector] = len(run.Tool.Driver.Rules)
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
				ID:        f.Detector,
				ShortDesc: &sarifMessage{Text: f.Detector + " detection"},
				Help:      &sarifMessage{Text: "Secret-like token detected. Review and rotate if valid."},
			})
		}
	}
	for _, f := range findings {
		idx := ruleIndex[f.Detector]
		run.Results = append(run.Results, sarifResult{
			RuleID:    f.Detector,
			RuleIndex: idx,
			Level:     sevToLevel(f.Severity),
			Message:   sarifMessage{Text: f.Detector + " detected"},
			Locations: []sarifLoc{{
				PhysicalLocation: sarifPhys{
					ArtifactLocation: sarifArt{URI: f.Path},
					Region:           sarifRegion{StartLine: f.Line, Snippet: &sarifSnippet{Text: f.Match}},
				},
			}},
		})
	}
	doc := sarif{Version: "2.1.0", Runs: []sarifRun{run}}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
