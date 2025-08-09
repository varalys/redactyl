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
	Name    string `json:"name"`
	Version string `json:"version"`
}

type sarifResult struct {
	RuleID    string       `json:"ruleId"`
	Level     string       `json:"level"`
	Message   sarifMessage `json:"message"`
	Locations []sarifLoc   `json:"locations"`
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
	StartLine int `json:"startLine"`
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
	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{Name: "redactyl", Version: time.Now().Format("2006.01.02")}},
	}
	for _, f := range findings {
		run.Results = append(run.Results, sarifResult{
			RuleID:  f.Detector,
			Level:   sevToLevel(f.Severity),
			Message: sarifMessage{Text: f.Detector + " detected"},
			Locations: []sarifLoc{{
				PhysicalLocation: sarifPhys{
					ArtifactLocation: sarifArt{URI: f.Path},
					Region:           sarifRegion{StartLine: f.Line},
				},
			}},
		})
	}
	doc := sarif{Version: "2.1.0", Runs: []sarifRun{run}}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
