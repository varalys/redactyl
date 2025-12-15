package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/redactyl/redactyl/internal/types"
)

type ScanRecord struct {
	Timestamp      time.Time        `json:"timestamp"`
	ScanID         string           `json:"scan_id"`
	Root           string           `json:"root"`
	TotalFindings  int              `json:"total_findings"`
	NewFindings    int              `json:"new_findings"`
	BaselinedCount int              `json:"baselined_count"`
	SeverityCounts map[string]int   `json:"severity_counts"`
	FilesScanned   int              `json:"files_scanned"`
	Duration       string           `json:"duration"`
	BaselineFile   string           `json:"baseline_file,omitempty"`
	TopFindings    []FindingSummary `json:"top_findings,omitempty"`
	AllFindings    []types.Finding  `json:"all_findings,omitempty"`
}

type FindingSummary struct {
	Path     string `json:"path"`
	Detector string `json:"detector"`
	Severity string `json:"severity"`
	Line     int    `json:"line"`
}

type AuditLog struct {
	logPath string
}

func NewAuditLog(root string) *AuditLog {
	gitDir := filepath.Join(root, ".git")
	logPath := filepath.Join(root, ".redactyl_audit.jsonl")
	if st, err := os.Stat(gitDir); err == nil && st.IsDir() {
		logPath = filepath.Join(gitDir, "redactyl_audit.jsonl")
	}
	return &AuditLog{logPath: logPath}
}

func (a *AuditLog) LoadHistory() ([]ScanRecord, error) {
	f, err := os.Open(a.logPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log: %w", err)
	}
	defer f.Close()

	var records []ScanRecord
	decoder := json.NewDecoder(f)
	for decoder.More() {
		var record ScanRecord
		if err := decoder.Decode(&record); err != nil {
			continue
		}
		records = append(records, record)
	}

	for i, j := 0, len(records)-1; i < j; i, j = i+1, j-1 {
		records[i], records[j] = records[j], records[i]
	}
	return records, nil
}

func (a *AuditLog) LogScan(record ScanRecord) error {
	if record.ScanID == "" {
		record.ScanID = fmt.Sprintf("scan_%d", time.Now().Unix())
	}

	// Restrict permissions to owner-only for audit log containing finding metadata
	f, err := os.OpenFile(a.logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open audit log: %w", err)
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	if err := encoder.Encode(record); err != nil {
		return fmt.Errorf("failed to write audit record: %w", err)
	}
	return nil
}

func (a *AuditLog) DeleteRecord(index int) error {
	records, err := a.LoadHistory()
	if err != nil {
		return err
	}

	if index < 0 || index >= len(records) {
		return fmt.Errorf("invalid index: %d", index)
	}

	records = append(records[:index], records[index+1:]...)

	for i, j := 0, len(records)-1; i < j; i, j = i+1, j-1 {
		records[i], records[j] = records[j], records[i]
	}

	f, err := os.Create(a.logPath)
	if err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	for _, record := range records {
		if err := encoder.Encode(record); err != nil {
			return fmt.Errorf("failed to write audit record: %w", err)
		}
	}
	return nil
}

func CreateScanRecord(
	root string,
	allFindings []types.Finding,
	newFindings []types.Finding,
	filesScanned int,
	duration time.Duration,
	baselineFile string,
) ScanRecord {
	severityCounts := make(map[string]int)
	for _, f := range allFindings {
		severityCounts[string(f.Severity)]++
	}

	topFindings := make([]FindingSummary, 0, 10)
	for i, f := range newFindings {
		if i >= 10 {
			break
		}
		topFindings = append(topFindings, FindingSummary{
			Path:     f.Path,
			Detector: f.Detector,
			Severity: string(f.Severity),
			Line:     f.Line,
		})
	}

	// Redact secrets from findings before storing in audit log
	redactedFindings := redactSecrets(allFindings)

	return ScanRecord{
		Timestamp:      time.Now(),
		Root:           root,
		TotalFindings:  len(allFindings),
		NewFindings:    len(newFindings),
		BaselinedCount: len(allFindings) - len(newFindings),
		SeverityCounts: severityCounts,
		FilesScanned:   filesScanned,
		Duration:       duration.String(),
		BaselineFile:   baselineFile,
		TopFindings:    topFindings,
		AllFindings:    redactedFindings,
	}
}

// redactSecrets returns a copy of findings with the Secret field redacted.
// This prevents actual secret values from being written to the audit log.
func redactSecrets(findings []types.Finding) []types.Finding {
	redacted := make([]types.Finding, len(findings))
	for i, f := range findings {
		redacted[i] = f
		if f.Secret != "" {
			redacted[i].Secret = "[REDACTED]"
		}
	}
	return redacted
}
