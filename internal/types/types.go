package types

// Severity is a coarse-grained risk level for a finding.
type Severity string

const (
	SevLow  Severity = "low"
	SevMed  Severity = "medium"
	SevHigh Severity = "high"
)

// Finding describes a potential secret or sensitive value detected at a path
// and line, including the detector ID, severity, and confidence in [0,1].
type Finding struct {
	Path       string            `json:"path"`
	Line       int               `json:"line"`
	Column     int               `json:"column,omitempty"` // Column number (0 if unknown)
	Match      string            `json:"match"`
	Secret     string            `json:"secret,omitempty"` // Actual secret value (may be redacted)
	Detector   string            `json:"detector"`
	Severity   Severity          `json:"severity"`
	Confidence float64           `json:"confidence"`
	Context    string            `json:"context,omitempty"`  // Additional context or description
	Metadata   map[string]string `json:"metadata,omitempty"` // Artifact-specific metadata
}
