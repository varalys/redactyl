package gitleaks

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBinaryManager(t *testing.T) {
	bm := NewBinaryManager("")
	assert.NotNil(t, bm)
	assert.NotEmpty(t, bm.cachePath)
	assert.Contains(t, bm.cachePath, ".redactyl")
}

func TestNewBinaryManager_CustomPath(t *testing.T) {
	customPath := "/custom/path/to/gitleaks"
	bm := NewBinaryManager(customPath)
	assert.Equal(t, customPath, bm.customPath)
}

func TestBinaryManager_Find_InPath(t *testing.T) {
	// This test only runs if gitleaks is actually in PATH
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("gitleaks not in PATH, skipping test")
	}

	bm := NewBinaryManager("")
	path, err := bm.Find()

	require.NoError(t, err)
	assert.NotEmpty(t, path)
	assert.FileExists(t, path)
}

func TestBinaryManager_Find_CustomPath(t *testing.T) {
	// Create a temp file to simulate a binary
	tmpDir := t.TempDir()
	fakeBinary := filepath.Join(tmpDir, "gitleaks")
	err := os.WriteFile(fakeBinary, []byte("fake"), 0755)
	require.NoError(t, err)

	bm := NewBinaryManager(fakeBinary)
	path, err := bm.Find()

	require.NoError(t, err)
	assert.Equal(t, fakeBinary, path)
}

func TestBinaryManager_Find_CustomPath_NotFound(t *testing.T) {
	bm := NewBinaryManager("/nonexistent/gitleaks")
	_, err := bm.Find()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "custom gitleaks path not found")
}

func TestBinaryManager_Find_NotFound(t *testing.T) {
	// Create a binary manager that won't find gitleaks
	bm := &BinaryManager{
		customPath: "",
		cachePath:  "/nonexistent/cache/path",
	}

	// Only test if gitleaks is NOT in PATH
	if _, err := exec.LookPath("gitleaks"); err == nil {
		t.Skip("gitleaks found in PATH, skipping not-found test")
	}

	_, err := bm.Find()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "gitleaks binary not found")
}

func TestBinaryManager_Version(t *testing.T) {
	// Find gitleaks in PATH or skip
	gitleaksPath, err := exec.LookPath("gitleaks")
	if err != nil {
		t.Skip("gitleaks not in PATH, skipping version test")
	}

	bm := NewBinaryManager("")
	version, err := bm.Version(gitleaksPath)

	require.NoError(t, err)
	assert.NotEmpty(t, version)
	// Version should be something like "8.18.0" or "8.18.1"
	assert.Regexp(t, `^\d+\.\d+\.\d+`, version)
}

func TestBinaryManager_Version_InvalidBinary(t *testing.T) {
	bm := NewBinaryManager("")
	_, err := bm.Version("/nonexistent/binary")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get gitleaks version")
}

func TestGetPlatform(t *testing.T) {
	platform := GetPlatform()
	assert.NotEmpty(t, platform)

	// Should contain OS and arch
	assert.Contains(t, platform, runtime.GOOS)

	// Common platforms
	validPlatforms := []string{
		"darwin_x64", "darwin_arm64",
		"linux_x64", "linux_arm64",
		"windows_x64",
	}

	// Platform should be one of the valid ones (or similar format)
	found := false
	for _, valid := range validPlatforms {
		if platform == valid {
			found = true
			break
		}
	}

	// If not an exact match, at least verify format
	if !found {
		assert.Regexp(t, `^[a-z]+_[a-z0-9]+$`, platform)
	}
}

func TestBinaryManager_Download_NotImplemented(t *testing.T) {
	bm := NewBinaryManager("")
	err := bm.Download("8.18.0")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "auto-download not yet implemented")
	assert.Contains(t, err.Error(), "brew install gitleaks") // Should have installation instructions
}
