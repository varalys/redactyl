package gitleaks

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
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
// version can be "latest" or a specific version like "8.18.0" or "v8.18.0".
// The binary is installed to the cache directory (~/.redactyl/bin).
func (bm *BinaryManager) Download(version string) error {
	// Resolve version to download
	downloadVersion := version
	if version == "latest" || version == "" {
		latestVer, err := getLatestVersion()
		if err != nil {
			return fmt.Errorf("failed to get latest gitleaks version: %w", err)
		}
		downloadVersion = latestVer
	}

	// Ensure version has 'v' prefix for GitHub releases
	if !strings.HasPrefix(downloadVersion, "v") {
		downloadVersion = "v" + downloadVersion
	}

	// Build download URL
	platform := GetPlatform()
	// Gitleaks uses version without 'v' in filename
	versionNoV := strings.TrimPrefix(downloadVersion, "v")

	var downloadURL string
	var isZip bool
	if runtime.GOOS == "windows" {
		downloadURL = fmt.Sprintf("https://github.com/gitleaks/gitleaks/releases/download/%s/gitleaks_%s_%s.zip",
			downloadVersion, versionNoV, platform)
		isZip = true
	} else {
		downloadURL = fmt.Sprintf("https://github.com/gitleaks/gitleaks/releases/download/%s/gitleaks_%s_%s.tar.gz",
			downloadVersion, versionNoV, platform)
		isZip = false
	}

	// Create cache directory
	if err := os.MkdirAll(bm.cachePath, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Download archive
	resp, err := http.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("failed to download gitleaks: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download gitleaks: HTTP %d from %s", resp.StatusCode, downloadURL)
	}

	// Extract binary
	binaryName := "gitleaks"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	destPath := filepath.Join(bm.cachePath, binaryName)

	if isZip {
		if err := extractFromZip(resp.Body, binaryName, destPath); err != nil {
			return fmt.Errorf("failed to extract gitleaks: %w", err)
		}
	} else {
		if err := extractFromTarGz(resp.Body, binaryName, destPath); err != nil {
			return fmt.Errorf("failed to extract gitleaks: %w", err)
		}
	}

	// Make executable on Unix-like systems
	if runtime.GOOS != "windows" {
		if err := os.Chmod(destPath, 0755); err != nil {
			return fmt.Errorf("failed to make gitleaks executable: %w", err)
		}
	}

	return nil
}

// GetPlatform returns the platform identifier for Gitleaks releases.
// Examples: "darwin_x64", "linux_arm64", "windows_x64"
func GetPlatform() string {
	os := runtime.GOOS
	arch := runtime.GOARCH

	// Map Go arch names to Gitleaks release names
	switch arch {
	case "amd64":
		arch = "x64"
	case "386":
		arch = "x32"
	}

	return fmt.Sprintf("%s_%s", os, arch)
}

// getLatestVersion fetches the latest release version from GitHub API.
func getLatestVersion() (string, error) {
	resp, err := http.Get("https://api.github.com/repos/gitleaks/gitleaks/releases/latest")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned HTTP %d", resp.StatusCode)
	}

	// Parse JSON to extract tag_name
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Simple JSON parsing - look for "tag_name":"vX.Y.Z"
	tagNamePrefix := `"tag_name":"`
	start := strings.Index(string(body), tagNamePrefix)
	if start == -1 {
		return "", fmt.Errorf("could not find tag_name in GitHub response")
	}
	start += len(tagNamePrefix)
	end := strings.Index(string(body[start:]), `"`)
	if end == -1 {
		return "", fmt.Errorf("malformed tag_name in GitHub response")
	}

	return string(body[start : start+end]), nil
}

// extractFromTarGz extracts a single file from a tar.gz archive.
func extractFromTarGz(r io.Reader, filename, destPath string) error {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Look for the gitleaks binary (could be in root or subdirectory)
		if strings.HasSuffix(header.Name, filename) {
			outFile, err := os.Create(destPath)
			if err != nil {
				return err
			}
			defer outFile.Close()

			if _, err := io.Copy(outFile, tr); err != nil {
				return err
			}
			return nil
		}
	}

	return fmt.Errorf("file %s not found in archive", filename)
}

// extractFromZip extracts a single file from a zip archive.
func extractFromZip(r io.Reader, filename, destPath string) error {
	// Read entire archive into memory (zip requires ReaderAt)
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	zr, err := zip.NewReader(&bytesReaderAt{data}, int64(len(data)))
	if err != nil {
		return err
	}

	for _, f := range zr.File {
		// Look for the gitleaks binary (could be in root or subdirectory)
		if strings.HasSuffix(f.Name, filename) {
			rc, err := f.Open()
			if err != nil {
				return err
			}
			defer rc.Close()

			outFile, err := os.Create(destPath)
			if err != nil {
				return err
			}
			defer outFile.Close()

			if _, err := io.Copy(outFile, rc); err != nil {
				return err
			}
			return nil
		}
	}

	return fmt.Errorf("file %s not found in archive", filename)
}

// bytesReaderAt implements io.ReaderAt for a byte slice.
type bytesReaderAt struct {
	data []byte
}

func (b *bytesReaderAt) ReadAt(p []byte, off int64) (n int, err error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	if off >= int64(len(b.data)) {
		return 0, io.EOF
	}
	n = copy(p, b.data[off:])
	if n < len(p) {
		err = io.EOF
	}
	return
}
