package gitleaks

import (
	"bytes"
	"encoding/json"
	"errors"
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

	requestedVersion := strings.TrimSpace(cfg.GetVersion())
	expectedVersion := ""
	if requestedVersion != "" && !strings.EqualFold(requestedVersion, "latest") {
		expectedVersion = normalizeVersion(requestedVersion)
	}

	binaryPath, err := bm.Find(expectedVersion)
	if err != nil {
		if !cfg.IsAutoDownloadEnabled() {
			msg := "gitleaks binary not found (auto-download disabled): %w\n\n" +
				"To fix this:\n" +
				"  1. Install Gitleaks:\n" +
				"     macOS:   brew install gitleaks\n" +
				"     Linux:   Download from https://github.com/gitleaks/gitleaks/releases\n" +
				"     Windows: Download from https://github.com/gitleaks/gitleaks/releases\n" +
				"  2. Or enable auto-download in config:\n" +
				"     gitleaks:\n" +
				"       auto_download: true\n" +
				"  3. Or specify explicit path:\n" +
				"     gitleaks:\n" +
				"       binary: /path/to/gitleaks"
			if errors.Is(err, errVersionMismatch) && expectedVersion != "" {
				return nil, fmt.Errorf("gitleaks binary version mismatch (expected %s): %w\n\n%s", expectedVersion, err, msg)
			}
			return nil, fmt.Errorf(msg, err)
		}

		downloadPath, dlErr := bm.Download(requestedVersion)
		if dlErr != nil {
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
		binaryPath = downloadPath
	}

	version, err := bm.Version(binaryPath)
	if err != nil {
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
	ctx := scanner.ScanContext{
		VirtualPath: path,
		RealPath:    path,
		Metadata:    map[string]string{},
	}
	return s.ScanBatch([]scanner.BatchInput{{
		Path:    path,
		Data:    data,
		Context: ctx,
	}})
}

// ScanWithContext implements scanner.Scanner with artifact context.
func (s *Scanner) ScanWithContext(ctx scanner.ScanContext, data []byte) ([]types.Finding, error) {
	if ctx.Metadata == nil {
		ctx.Metadata = map[string]string{}
	}
	targetPath := ctx.VirtualPath
	if targetPath == "" {
		targetPath = ctx.RealPath
	}
	if targetPath == "" {
		targetPath = "stdin"
	}
	return s.ScanBatch([]scanner.BatchInput{{
		Path:    targetPath,
		Data:    data,
		Context: ctx,
	}})
}

// ScanBatch implements scanner.Scanner by scanning multiple inputs in a single gitleaks invocation.
func (s *Scanner) ScanBatch(inputs []scanner.BatchInput) ([]types.Finding, error) {
	if len(inputs) == 0 {
		return nil, nil
	}

	tmpDir, err := os.MkdirTemp("", "redactyl-batch-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp workspace: %w", err)
	}
	// Set restrictive permissions on temp directory containing sensitive data
	if err := os.Chmod(tmpDir, 0700); err != nil {
		_ = os.RemoveAll(tmpDir) //nolint:errcheck
		return nil, fmt.Errorf("failed to secure temp workspace: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(tmpDir) //nolint:errcheck // Best-effort cleanup
	}()

	fileContexts := make(map[string]scanner.ScanContext, len(inputs)*3)
	for i, in := range inputs {
		ctx := normalizeContext(in.Context, in.Path)

		filename := deriveFilename(i, ctx)
		fullPath := filepath.Join(tmpDir, filename)
		if err := os.WriteFile(fullPath, in.Data, 0600); err != nil {
			return nil, fmt.Errorf("failed to write temp file: %w", err)
		}

		fileContexts[filename] = ctx
		fileContexts[fullPath] = ctx
		if !strings.HasPrefix(filename, "./") {
			fileContexts["./"+filename] = ctx
		}
	}

	reportFile, err := os.CreateTemp("", "redactyl-report-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create report file: %w", err)
	}
	reportPath := reportFile.Name()
	_ = reportFile.Close() //nolint:errcheck // Only need the path
	defer func() {
		_ = os.Remove(reportPath) //nolint:errcheck // Cleanup
	}()

	args := []string{
		"detect",
		"--no-git",
		"--report-format", "json",
		"--report-path", reportPath,
		"--source", tmpDir,
		"--exit-code", "0",
	}
	if s.configPath != "" {
		args = append(args, "--config", s.configPath)
	}

	cmd := exec.Command(s.binaryPath, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, wrapGitleaksError(err, stderr.String())
	}

	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read gitleaks report: %w", err)
	}

	if len(reportData) == 0 {
		return nil, nil
	}

	var gitleaksFindings []GitleaksFinding
	if err := json.Unmarshal(reportData, &gitleaksFindings); err != nil {
		return nil, fmt.Errorf("failed to parse gitleaks JSON output: %w\n\n"+
			"This usually indicates a version compatibility issue.\n"+
			"Current Gitleaks version: %s\n"+
			"Recommended: 8.18.0 or later\n\n"+
			"To update Gitleaks:\n"+
			"  macOS:   brew upgrade gitleaks\n"+
			"  Other:   Set gitleaks.version in config or download from releases", err, s.version)
	}

	var findings []types.Finding
	for _, gf := range gitleaksFindings {
		ctx, ok := fileContexts[gf.File]
		if !ok {
			abs := filepath.Join(tmpDir, gf.File)
			if c2, ok2 := fileContexts[abs]; ok2 {
				ctx = c2
				ok = true
			}
		}
		if !ok {
			ctx = normalizeContext(scanner.ScanContext{}, gf.File)
		}
		findings = append(findings, s.convertFindings([]GitleaksFinding{gf}, ctx)...)
	}

	return findings, nil
}

func wrapGitleaksError(err error, stderr string) error {
	if exitErr, ok := err.(*exec.ExitError); ok {
		exitCode := exitErr.ExitCode()
		errorMsg := fmt.Sprintf("gitleaks failed (exit code %d)", exitCode)

		switch {
		case contains(stderr, "config"), contains(stderr, ".toml"):
			errorMsg += "\n\nConfig file error detected. Check your .gitleaks.toml file:\n" +
				"  - Verify TOML syntax is valid\n" +
				"  - Check that all regex patterns are properly escaped\n" +
				"  - See https://github.com/gitleaks/gitleaks#configuration for examples"
		case contains(stderr, "permission denied"):
			errorMsg += "\n\nPermission denied. Check:\n" +
				"  - Gitleaks binary has execute permissions\n" +
				"  - You have read access to the files being scanned"
		case contains(stderr, "invalid"), contains(stderr, "syntax"):
			errorMsg += "\n\nInvalid configuration or syntax error."
		}

		errorMsg += fmt.Sprintf("\n\nGitleaks error output:\n%s", stderr)
		return fmt.Errorf("%s", errorMsg)
	}
	return fmt.Errorf("gitleaks execution failed: %w\n\nError output:\n%s", err, stderr)
}

func normalizeContext(ctx scanner.ScanContext, fallback string) scanner.ScanContext {
	out := scanner.ScanContext{
		VirtualPath: ctx.VirtualPath,
		RealPath:    ctx.RealPath,
		Metadata:    nil,
	}
	if out.VirtualPath == "" {
		out.VirtualPath = fallback
	}
	if out.RealPath == "" {
		out.RealPath = fallback
	}
	if ctx.Metadata != nil {
		meta := make(map[string]string, len(ctx.Metadata))
		for k, v := range ctx.Metadata {
			meta[k] = v
		}
		out.Metadata = meta
	} else {
		out.Metadata = map[string]string{}
	}
	return out
}

func deriveFilename(idx int, ctx scanner.ScanContext) string {
	ext := pickExtension(ctx)
	if ext == "" {
		ext = ".txt"
	}
	return fmt.Sprintf("%05d_input%s", idx, ext)
}

func pickExtension(ctx scanner.ScanContext) string {
	if ext := extensionFromPath(ctx.VirtualPath); ext != "" {
		return ext
	}
	if ext := extensionFromPath(ctx.RealPath); ext != "" {
		return ext
	}
	return ""
}

func extensionFromPath(path string) string {
	if path == "" {
		return ""
	}
	base := path
	if idx := strings.LastIndex(base, scanner.VirtualPathSeparator); idx >= 0 {
		base = base[idx+len(scanner.VirtualPathSeparator):]
	}
	base = filepath.Base(base)
	if dot := strings.LastIndex(base, "."); dot >= 0 && dot < len(base)-1 {
		return base[dot:]
	}
	return ""
}

// Version implements scanner.Scanner.
func (s *Scanner) Version() (string, error) {
	return s.version, nil
}

// Detectors implements scanner.Scanner.
func (s *Scanner) Detectors() ([]string, error) {
	return []string{
		"github-pat", "github-fine-grained-pat", "github-oauth", "github-app-token",
		"aws-access-key", "aws-secret-key", "aws-mws-key",
		"stripe-access-token", "stripe-secret-key",
		"slack-webhook-url", "slack-bot-token", "slack-app-token",
		"google-api-key", "google-oauth", "gcp-service-account",
		"gitlab-pat", "gitlab-pipeline-token", "gitlab-runner-token",
		"sendgrid-api-key",
		"openai-api-key",
		"anthropic-api-key",
		"npm-access-token",
		"pypi-token",
		"docker-config-auth",
		"jwt",
		"private-key",
		"generic-api-key",
		// Note: This is a subset for display. Gitleaks has 200+ rules.
	}, nil
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

		for k, v := range ctx.Metadata {
			finding.Metadata[k] = v
		}
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

func mapGitleaksToConfidence(f GitleaksFinding) float64 {
	confidence := 0.8

	if f.Entropy > 0 {
		switch {
		case f.Entropy > 4.5:
			confidence = 0.9
		case f.Entropy > 3.5:
			confidence = 0.75
		default:
			confidence = 0.6
		}
	}

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

func DetectConfigPath(repoRoot string) string {
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

func contains(s, substr string) bool {
	return bytes.Contains([]byte(strings.ToLower(s)), []byte(strings.ToLower(substr)))
}
