package gitleaks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/redactyl/redactyl/internal/config"
	"github.com/redactyl/redactyl/internal/scanner"
	"github.com/redactyl/redactyl/internal/types"
)

// Scanner implements the scanner.Scanner interface using Gitleaks.
type Scanner struct {
	binaryPath string
	configPath string
	version    string
}

// NewScanner creates a new Gitleaks scanner from configuration.
func NewScanner(cfg config.GitleaksConfig) (*Scanner, error) {
	bm := NewBinaryManager(cfg.GetBinaryPath())

	// Try to find existing binary
	binaryPath, err := bm.Find()
	if err != nil {
		// If auto-download is enabled, attempt download
		if cfg.IsAutoDownloadEnabled() {
			version := cfg.GetVersion()
			if version == "" {
				version = "latest"
			}
			if dlErr := bm.Download(version); dlErr != nil {
				return nil, fmt.Errorf("gitleaks binary not found and auto-download failed: %w\n\n"+
					"To fix this:\n"+
					"  1. Install Gitleaks manually:\n"+
					"     macOS:   brew install gitleaks\n"+
					"     Linux:   Download from https://github.com/gitleaks/gitleaks/releases\n"+
					"     Windows: Download from https://github.com/gitleaks/gitleaks/releases\n"+
					"  2. Or specify explicit path in config:\n"+
					"     gitleaks:\n"+
					"       binary: /path/to/gitleaks\n"+
					"  3. Or check network connectivity for auto-download", dlErr)
			}
			// Try finding again after download
			binaryPath, err = bm.Find()
			if err != nil {
				return nil, fmt.Errorf("gitleaks binary not found after successful download: %w\n"+
					"This is unexpected. Please report this issue at:\n"+
					"https://github.com/redactyl/redactyl/issues", err)
			}
		} else {
			return nil, fmt.Errorf("gitleaks binary not found (auto-download disabled): %w\n\n"+
				"To fix this:\n"+
				"  1. Install Gitleaks:\n"+
				"     macOS:   brew install gitleaks\n"+
				"     Linux:   Download from https://github.com/gitleaks/gitleaks/releases\n"+
				"     Windows: Download from https://github.com/gitleaks/gitleaks/releases\n"+
				"  2. Or enable auto-download in config:\n"+
				"     gitleaks:\n"+
				"       auto_download: true\n"+
				"  3. Or specify explicit path:\n"+
				"     gitleaks:\n"+
				"       binary: /path/to/gitleaks", err)
		}
	}

	// Get version
	version, err := bm.Version(binaryPath)
	if err != nil {
		// Non-fatal, just log
		version = "unknown"
	}

	return &Scanner{
		binaryPath: binaryPath,
		configPath: cfg.GetConfigPath(),
		version:    version,
	}, nil
}

// Scan implements scanner.Scanner.
func (s *Scanner) Scan(path string, data []byte) ([]types.Finding, error) {
	return s.ScanWithContext(scanner.ScanContext{
		VirtualPath: path,
		RealPath:    path,
	}, data)
}

// ScanWithContext implements scanner.Scanner with artifact context.
func (s *Scanner) ScanWithContext(ctx scanner.ScanContext, data []byte) ([]types.Finding, error) {
	// Write data to temp file for Gitleaks to scan
	tmpfile, err := os.CreateTemp("", "redactyl-scan-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer func() {
		_ = os.Remove(tmpfile.Name()) //nolint:errcheck // Cleanup, error is not actionable
	}()
	defer func() {
		_ = tmpfile.Close() //nolint:errcheck // Cleanup, error is not actionable
	}()

	if _, err := tmpfile.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write temp file: %w", err)
	}
	if err := tmpfile.Close(); err != nil {
		return nil, fmt.Errorf("failed to close temp file: %w", err)
	}

	// Create temp file for report output
	reportFile, err := os.CreateTemp("", "redactyl-report-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create report file: %w", err)
	}
	reportPath := reportFile.Name()
	_ = reportFile.Close() //nolint:errcheck // Just getting the path, error is not actionable
	defer func() {
		_ = os.Remove(reportPath) //nolint:errcheck // Cleanup, error is not actionable
	}()

	// Build gitleaks command
	args := []string{
		"detect",
		"--no-git", // Don't use git, just scan files
		"--report-format", "json",
		"--report-path", reportPath,
		"--source", tmpfile.Name(),
		"--exit-code", "0", // Don't exit with error on findings
	}

	if s.configPath != "" {
		args = append(args, "--config", s.configPath)
	}

	// Execute gitleaks
	cmd := exec.Command(s.binaryPath, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		stderrStr := stderr.String()

		// Check if this is just a findings error (exit code 1)
		if exitErr, ok := err.(*exec.ExitError); ok {
			// With --exit-code 0, we shouldn't get exit code 1
			// If we do, something went wrong
			exitCode := exitErr.ExitCode()

			// Provide helpful error messages based on common failure modes
			errorMsg := fmt.Sprintf("gitleaks failed (exit code %d)", exitCode)

			// Check for common error patterns
			if contains(stderrStr, "config") || contains(stderrStr, ".toml") {
				errorMsg += "\n\nConfig file error detected. Check your .gitleaks.toml file:\n" +
					"  - Verify TOML syntax is valid\n" +
					"  - Check that all regex patterns are properly escaped\n" +
					"  - See https://github.com/gitleaks/gitleaks#configuration for examples"
			} else if contains(stderrStr, "permission denied") {
				errorMsg += "\n\nPermission denied. Check:\n" +
					"  - Gitleaks binary has execute permissions\n" +
					"  - You have read access to the files being scanned"
			} else if contains(stderrStr, "invalid") || contains(stderrStr, "syntax") {
				errorMsg += "\n\nInvalid configuration or syntax error."
			}

			errorMsg += fmt.Sprintf("\n\nGitleaks error output:\n%s", stderrStr)
			return nil, fmt.Errorf("%s", errorMsg)
		}
		return nil, fmt.Errorf("gitleaks execution failed: %w\n\nError output:\n%s", err, stderrStr)
	}

	// Read and parse JSON report
	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read gitleaks report: %w", err)
	}

	var gitleaksFindings []GitleaksFinding
	if len(reportData) > 0 {
		if err := json.Unmarshal(reportData, &gitleaksFindings); err != nil {
			return nil, fmt.Errorf("failed to parse gitleaks JSON output: %w\n\n"+
				"This usually indicates a version compatibility issue.\n"+
				"Current Gitleaks version: %s\n"+
				"Recommended: 8.18.0 or later\n\n"+
				"To update Gitleaks:\n"+
				"  macOS:   brew upgrade gitleaks\n"+
				"  Other:   Set gitleaks.version in config or download from releases", err, s.version)
		}
	}

	// Convert to Redactyl findings
	return s.convertFindings(gitleaksFindings, ctx), nil
}

// Version implements scanner.Scanner.
func (s *Scanner) Version() (string, error) {
	return s.version, nil
}

// convertFindings maps Gitleaks findings to Redactyl findings.
func (s *Scanner) convertFindings(gf []GitleaksFinding, ctx scanner.ScanContext) []types.Finding {
	var findings []types.Finding

	for _, f := range gf {
		confidence := mapGitleaksToConfidence(f)
		finding := types.Finding{
			Path:       ctx.VirtualPath, // Use virtual path, not temp file path
			Detector:   f.RuleID,
			Match:      f.Match,
			Secret:     f.Secret,
			Line:       f.StartLine,
			Column:     f.StartColumn,
			Context:    f.Description,
			Confidence: confidence,
			Severity:   mapConfidenceToSeverity(confidence),
			Metadata:   make(map[string]string),
		}

		// Copy context metadata
		for k, v := range ctx.Metadata {
			finding.Metadata[k] = v
		}

		// Add gitleaks-specific metadata
		finding.Metadata["gitleaks_rule_id"] = f.RuleID
		if f.Commit != "" {
			finding.Metadata["commit"] = f.Commit
		}
		if f.Entropy > 0 {
			finding.Metadata["entropy"] = fmt.Sprintf("%.2f", f.Entropy)
		}

		findings = append(findings, finding)
	}

	return findings
}

// GitleaksFinding represents Gitleaks JSON output format.
type GitleaksFinding struct {
	Description string   `json:"Description"`
	RuleID      string   `json:"RuleID"`
	Match       string   `json:"Match"`
	Secret      string   `json:"Secret"`
	StartLine   int      `json:"StartLine"`
	EndLine     int      `json:"EndLine"`
	StartColumn int      `json:"StartColumn"`
	EndColumn   int      `json:"EndColumn"`
	File        string   `json:"File"`
	Commit      string   `json:"Commit"`
	Entropy     float64  `json:"Entropy,omitempty"`
	Author      string   `json:"Author,omitempty"`
	Email       string   `json:"Email,omitempty"`
	Date        string   `json:"Date,omitempty"`
	Message     string   `json:"Message,omitempty"`
	Tags        []string `json:"Tags,omitempty"`
	Fingerprint string   `json:"Fingerprint,omitempty"`
}

// mapGitleaksToConfidence maps Gitleaks findings to a confidence score.
// Gitleaks doesn't provide confidence scores, so we use heuristics:
// - High entropy findings are generally less reliable (more false positives)
// - Rules with specific formats/prefixes are more reliable
// - Default to 0.8 as a reasonable baseline
func mapGitleaksToConfidence(f GitleaksFinding) float64 {
	// Start with default confidence
	confidence := 0.8

	// Entropy-based findings are less reliable
	if f.Entropy > 0 {
		// Higher entropy = lower confidence
		// Typical entropy range: 3.0-5.0 for real secrets
		switch {
		case f.Entropy > 4.5:
			confidence = 0.9
		case f.Entropy > 3.5:
			confidence = 0.75
		default:
			confidence = 0.6
		}
	}

	// Specific rule patterns are more reliable
	// These are common high-confidence patterns from Gitleaks
	highConfidenceRules := []string{
		"aws-access-token",
		"github-pat",
		"github-fine-grained-pat",
		"github-oauth",
		"npm-access-token",
		"pypi-upload-token",
		"slack-access-token",
		"stripe-access-token",
	}

	for _, rule := range highConfidenceRules {
		if f.RuleID == rule {
			confidence = 0.95
			break
		}
	}

	return confidence
}

// DetectConfigPath searches for a .gitleaks.toml file in common locations.
// Returns empty string if not found.
func DetectConfigPath(repoRoot string) string {
	// Search order:
	// 1. Repo root
	// 2. .gitleaks/ subdirectory
	// 3. .github/ subdirectory (common location)

	candidates := []string{
		filepath.Join(repoRoot, ".gitleaks.toml"),
		filepath.Join(repoRoot, ".gitleaks", "config.toml"),
		filepath.Join(repoRoot, ".github", ".gitleaks.toml"),
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

// mapConfidenceToSeverity maps a confidence score to a severity level.
// This follows the Redactyl convention:
// - High confidence (0.9+) -> High severity
// - Medium confidence (0.7-0.9) -> Medium severity
// - Low confidence (< 0.7) -> Low severity
func mapConfidenceToSeverity(confidence float64) types.Severity {
	switch {
	case confidence >= 0.9:
		return types.SevHigh
	case confidence >= 0.7:
		return types.SevMed
	default:
		return types.SevLow
	}
}

// contains is a simple helper to check if a string contains a substring (case-insensitive).
func contains(s, substr string) bool {
	return bytes.Contains([]byte(strings.ToLower(s)), []byte(strings.ToLower(substr)))
}
