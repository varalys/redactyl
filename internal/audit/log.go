package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/redactyl/redactyl/internal/types"
)

// ScanRecord represents a single scan event for audit purposes
type ScanRecord struct {
	Timestamp      time.Time        `json:"timestamp"`
	ScanID         string           `json:"scan_id"` // Unique ID for this scan
	Root           string           `json:"root"`
	TotalFindings  int              `json:"total_findings"`
	NewFindings    int              `json:"new_findings"`    // Findings not in baseline
	BaselinedCount int              `json:"baselined_count"` // Findings in baseline
	SeverityCounts map[string]int   `json:"severity_counts"` // High, medium, low counts
	FilesScanned   int              `json:"files_scanned"`
	Duration       string           `json:"duration"`
	BaselineFile   string           `json:"baseline_file,omitempty"`
	TopFindings    []FindingSummary `json:"top_findings,omitempty"` // Sample of findings (max 10)
	AllFindings    []types.Finding  `json:"all_findings,omitempty"` // Complete findings for historical viewing
}

// FindingSummary is a simplified finding for audit logs
type FindingSummary struct {
	Path     string `json:"path"`
	Detector string `json:"detector"`
	Severity string `json:"severity"`
	Line     int    `json:"line"`
}

// AuditLog manages the audit trail
type AuditLog struct {
	logPath string
}

// NewAuditLog creates a new audit log manager
func NewAuditLog(root string) *AuditLog {
	// Store audit logs in .git directory or repo root
	gitDir := filepath.Join(root, ".git")
	logPath := filepath.Join(root, ".redactyl_audit.jsonl")

	if st, err := os.Stat(gitDir); err == nil && st.IsDir() {
		logPath = filepath.Join(gitDir, "redactyl_audit.jsonl")
	}

	return &AuditLog{logPath: logPath}
}

// LoadHistory reads all scan records from the audit log
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
			// Skip malformed lines
			continue
		}
		records = append(records, record)
	}

	// Reverse so newest is first
	for i, j := 0, len(records)-1; i < j; i, j = i+1, j-1 {
		records[i], records[j] = records[j], records[i]
	}

	return records, nil
}

// LogScan appends a scan record to the audit log
func (a *AuditLog) LogScan(record ScanRecord) error {
	// Generate scan ID if not provided
	if record.ScanID == "" {
		record.ScanID = fmt.Sprintf("scan_%d", time.Now().Unix())
	}

	// Open file in append mode
	f, err := os.OpenFile(a.logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open audit log: %w", err)
	}
	defer f.Close()

	// Write as JSON Lines (one JSON object per line)
	encoder := json.NewEncoder(f)
	if err := encoder.Encode(record); err != nil {
		return fmt.Errorf("failed to write audit record: %w", err)
	}

	return nil
}

// DeleteRecord removes a scan record by index (0 = newest)
func (a *AuditLog) DeleteRecord(index int) error {
	records, err := a.LoadHistory()
	if err != nil {
		return err
	}

	if index < 0 || index >= len(records) {
		return fmt.Errorf("invalid index: %d", index)
	}

	// Remove the record at index (records are already newest-first)
	records = append(records[:index], records[index+1:]...)

	// Reverse back to oldest-first for writing
	for i, j := 0, len(records)-1; i < j; i, j = i+1, j-1 {
		records[i], records[j] = records[j], records[i]
	}

	// Rewrite the entire file
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

// CreateScanRecord builds an audit record from scan results
func CreateScanRecord(
	root string,
	allFindings []types.Finding,
	newFindings []types.Finding,
	filesScanned int,
	duration time.Duration,
	baselineFile string,
) ScanRecord {
	// Count severities
	severityCounts := make(map[string]int)
	for _, f := range allFindings {
		severityCounts[string(f.Severity)]++
	}

	// Extract top findings (max 10 new findings)
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
		AllFindings:    allFindings, // Store complete findings for historical viewing
	}
}
