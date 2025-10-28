package gitleaks

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// BinaryManager handles detection and installation of the Gitleaks binary.
type BinaryManager struct {
	customPath string
	cachePath  string
}

// NewBinaryManager creates a new binary manager.
// customPath: optional explicit path to gitleaks binary
// cachePath: directory to cache downloaded binaries (defaults to ~/.redactyl/bin)
func NewBinaryManager(customPath string) *BinaryManager {
	homeDir, _ := os.UserHomeDir()
	cachePath := filepath.Join(homeDir, ".redactyl", "bin")

	return &BinaryManager{
		customPath: customPath,
		cachePath:  cachePath,
	}
}

// Find locates the Gitleaks binary using the following search order:
// 1. Custom path (if provided)
// 2. $PATH lookup
// 3. Cached binary in ~/.redactyl/bin/gitleaks
// Returns the path to the binary or an error if not found.
func (bm *BinaryManager) Find() (string, error) {
	// 1. Check custom path first
	if bm.customPath != "" {
		if _, err := os.Stat(bm.customPath); err == nil {
			return bm.customPath, nil
		}
		return "", fmt.Errorf("custom gitleaks path not found: %s", bm.customPath)
	}

	// 2. Check $PATH
	if path, err := exec.LookPath("gitleaks"); err == nil {
		return path, nil
	}

	// 3. Check cached binary
	cachedPath := filepath.Join(bm.cachePath, "gitleaks")
	if runtime.GOOS == "windows" {
		cachedPath += ".exe"
	}
	if _, err := os.Stat(cachedPath); err == nil {
		return cachedPath, nil
	}

	return "", fmt.Errorf("gitleaks binary not found in PATH or cache (%s)", cachedPath)
}

// Version runs gitleaks --version and parses the output.
// Returns the version string (e.g., "8.18.0") or an error.
func (bm *BinaryManager) Version(binaryPath string) (string, error) {
	cmd := exec.Command(binaryPath, "version")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get gitleaks version: %w", err)
	}

	// Parse version from output
	// Expected format: "v8.18.0" or "8.18.0" or similar
	version := strings.TrimSpace(string(output))
	version = strings.TrimPrefix(version, "v")
	version = strings.TrimPrefix(version, "version ")

	// Take first line if multi-line
	if lines := strings.Split(version, "\n"); len(lines) > 0 {
		version = strings.TrimSpace(lines[0])
	}

	return version, nil
}

// Download downloads and installs the Gitleaks binary from GitHub releases.
// This is a placeholder for future implementation using go-github-selfupdate or similar.
// For now, it returns an error directing users to install manually.
func (bm *BinaryManager) Download(version string) error {
	// TODO: Implement auto-download using rhysd/go-github-selfupdate or similar
	// For MVP, we'll require manual installation

	return fmt.Errorf("auto-download not yet implemented: please install gitleaks manually\n" +
		"  macOS:   brew install gitleaks\n" +
		"  Linux:   https://github.com/gitleaks/gitleaks/releases\n" +
		"  Windows: https://github.com/gitleaks/gitleaks/releases")
}

// GetPlatform returns the platform identifier for Gitleaks releases.
// Examples: "darwin_amd64", "linux_arm64", "windows_amd64"
func GetPlatform() string {
	os := runtime.GOOS
	arch := runtime.GOARCH

	// Map Go arch names to Gitleaks release names if needed
	switch arch {
	case "amd64":
		arch = "x64"
	case "386":
		arch = "x32"
	}

	return fmt.Sprintf("%s_%s", os, arch)
}
