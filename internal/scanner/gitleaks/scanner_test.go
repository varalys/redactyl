package gitleaks

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redactyl/redactyl/internal/config"
	"github.com/redactyl/redactyl/internal/scanner"
)

func TestNewScanner(t *testing.T) {
	// Skip if gitleaks not available
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("gitleaks not in PATH, skipping test")
	}

	cfg := config.GitleaksConfig{}
	autoDownload := false
	cfg.AutoDownload = &autoDownload // Don't try to download in tests

	s, err := NewScanner(cfg)
	require.NoError(t, err)
	assert.NotNil(t, s)
	assert.NotEmpty(t, s.binaryPath)
	assert.NotEmpty(t, s.version)
}

func TestNewScanner_CustomBinary(t *testing.T) {
	// Create a fake binary for testing
	tmpDir := t.TempDir()
	fakeBinary := filepath.Join(tmpDir, "gitleaks")

	// Create a simple script that acts like gitleaks version
	script := `#!/bin/sh
if [ "$1" = "version" ]; then
  echo "8.18.0"
  exit 0
fi
exit 1
`
	err := os.WriteFile(fakeBinary, []byte(script), 0755)
	require.NoError(t, err)

	cfg := config.GitleaksConfig{}
	cfg.BinaryPath = &fakeBinary

	s, err := NewScanner(cfg)
	require.NoError(t, err)
	assert.Equal(t, fakeBinary, s.binaryPath)
}

func TestNewScanner_NotFound(t *testing.T) {
	cfg := config.GitleaksConfig{}
	customPath := "/nonexistent/gitleaks"
	cfg.BinaryPath = &customPath
	autoDownload := false
	cfg.AutoDownload = &autoDownload

	_, err := NewScanner(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestScanner_Scan(t *testing.T) {
	// Skip if gitleaks not available
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("gitleaks not in PATH, skipping integration test")
	}

	cfg := config.GitleaksConfig{}
	autoDownload := false
	cfg.AutoDownload = &autoDownload

	s, err := NewScanner(cfg)
	require.NoError(t, err)

	// Test with a pattern that Gitleaks recognizes (generic-api-key with high entropy)
	testData := []byte("token = ghp_ABCDEFGHIJKLMNOPQRST1234567890ab")

	findings, err := s.Scan("test.txt", testData)
	require.NoError(t, err)

	// Should detect at least one finding
	assert.NotEmpty(t, findings, "Expected gitleaks to detect token")

	if len(findings) > 0 {
		f := findings[0]
		assert.Equal(t, "test.txt", f.Path)
		assert.NotEmpty(t, f.Detector)
		assert.Contains(t, f.Match, "ghp_")
		assert.Greater(t, f.Confidence, 0.0)
		assert.NotEmpty(t, f.Severity)
	}
}

func TestScanner_ScanWithContext(t *testing.T) {
	// Skip if gitleaks not available
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("gitleaks not in PATH, skipping integration test")
	}

	cfg := config.GitleaksConfig{}
	autoDownload := false
	cfg.AutoDownload = &autoDownload

	s, err := NewScanner(cfg)
	require.NoError(t, err)

	// Test with virtual path context
	ctx := scanner.ScanContext{
		VirtualPath: "archive.zip::secrets.txt",
		RealPath:    "/tmp/tempfile",
		Metadata: map[string]string{
			"archive": "archive.zip",
			"entry":   "secrets.txt",
		},
	}

	testData := []byte("github_token = ghp_1234567890abcdefghijklmnopqrstuvwxyz12")

	findings, err := s.ScanWithContext(ctx, testData)
	require.NoError(t, err)

	if len(findings) > 0 {
		f := findings[0]
		// Should preserve virtual path
		assert.Equal(t, "archive.zip::secrets.txt", f.Path)
		// Should preserve metadata
		assert.Equal(t, "archive.zip", f.Metadata["archive"])
		assert.Equal(t, "secrets.txt", f.Metadata["entry"])
		// Should have gitleaks metadata
		assert.NotEmpty(t, f.Metadata["gitleaks_rule_id"])
	}
}

func TestScanner_Version(t *testing.T) {
	// Skip if gitleaks not available
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("gitleaks not in PATH, skipping test")
	}

	cfg := config.GitleaksConfig{}
	autoDownload := false
	cfg.AutoDownload = &autoDownload

	s, err := NewScanner(cfg)
	require.NoError(t, err)

	version, err := s.Version()
	require.NoError(t, err)
	assert.NotEmpty(t, version)
	assert.NotEqual(t, "unknown", version)
}

func TestMapGitleaksToConfidence(t *testing.T) {
	tests := []struct {
		name     string
		finding  GitleaksFinding
		expected float64
	}{
		{
			name: "high confidence rule",
			finding: GitleaksFinding{
				RuleID: "aws-access-token",
			},
			expected: 0.95,
		},
		{
			name: "high entropy",
			finding: GitleaksFinding{
				RuleID:  "generic-api-key",
				Entropy: 4.8,
			},
			expected: 0.9,
		},
		{
			name: "medium entropy",
			finding: GitleaksFinding{
				RuleID:  "generic-api-key",
				Entropy: 3.8,
			},
			expected: 0.75,
		},
		{
			name: "low entropy",
			finding: GitleaksFinding{
				RuleID:  "generic-api-key",
				Entropy: 3.0,
			},
			expected: 0.6,
		},
		{
			name: "default",
			finding: GitleaksFinding{
				RuleID: "custom-rule",
			},
			expected: 0.8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			confidence := mapGitleaksToConfidence(tt.finding)
			assert.Equal(t, tt.expected, confidence)
		})
	}
}

func TestDetectConfigPath(t *testing.T) {
	tmpDir := t.TempDir()

	// No config file
	path := DetectConfigPath(tmpDir)
	assert.Empty(t, path)

	// Create .gitleaks.toml in root
	configPath := filepath.Join(tmpDir, ".gitleaks.toml")
	err := os.WriteFile(configPath, []byte("# test config"), 0644)
	require.NoError(t, err)

	path = DetectConfigPath(tmpDir)
	assert.Equal(t, configPath, path)

	// Test with .gitleaks/ subdirectory
	tmpDir2 := t.TempDir()
	gitleaksDir := filepath.Join(tmpDir2, ".gitleaks")
	err = os.MkdirAll(gitleaksDir, 0755)
	require.NoError(t, err)

	configPath2 := filepath.Join(gitleaksDir, "config.toml")
	err = os.WriteFile(configPath2, []byte("# test config"), 0644)
	require.NoError(t, err)

	path = DetectConfigPath(tmpDir2)
	assert.Equal(t, configPath2, path)
}

func TestScanner_EmptyData(t *testing.T) {
	// Skip if gitleaks not available
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("gitleaks not in PATH, skipping test")
	}

	cfg := config.GitleaksConfig{}
	autoDownload := false
	cfg.AutoDownload = &autoDownload

	s, err := NewScanner(cfg)
	require.NoError(t, err)

	findings, err := s.Scan("empty.txt", []byte(""))
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestScanner_NoSecrets(t *testing.T) {
	// Skip if gitleaks not available
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("gitleaks not in PATH, skipping test")
	}

	cfg := config.GitleaksConfig{}
	autoDownload := false
	cfg.AutoDownload = &autoDownload

	s, err := NewScanner(cfg)
	require.NoError(t, err)

	testData := []byte("This is just normal text with no secrets.")

	findings, err := s.Scan("normal.txt", testData)
	require.NoError(t, err)
	assert.Empty(t, findings)
}
