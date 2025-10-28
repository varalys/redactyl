package scanner

import "github.com/redactyl/redactyl/internal/types"

// Scanner defines the interface for secret detection engines.
// Implementations include Gitleaks integration and potential future scanners.
type Scanner interface {
	// Scan scans content at the given path and returns findings.
	// The path is used for context and may be a real file path or virtual path.
	Scan(path string, data []byte) ([]types.Finding, error)

	// ScanWithContext scans content with additional artifact context.
	// This is useful for nested artifacts where the path needs to show
	// the full chain (e.g., "archive.zip::inner.tar::file.txt").
	ScanWithContext(ctx ScanContext, data []byte) ([]types.Finding, error)

	// Version returns the scanner version information.
	Version() (string, error)
}

// ScanContext provides additional context for scanning artifacts.
// It allows scanners to enrich findings with metadata about where
// the content originated (layer, archive entry, manifest, etc.).
type ScanContext struct {
	// VirtualPath is the display path showing the artifact chain.
	// Example: "myapp.tar::layer-sha256:abc123::etc/secrets/config.yaml"
	VirtualPath string

	// RealPath is the actual filesystem path (if content is on disk).
	// For in-memory scanning, this may be empty or a temp file path.
	RealPath string

	// Metadata contains artifact-specific context.
	// Examples:
	//   - "archive": "myapp.zip"
	//   - "layer_digest": "sha256:abc123..."
	//   - "layer_index": "5"
	//   - "kubernetes_kind": "Secret"
	//   - "kubernetes_namespace": "default"
	Metadata map[string]string
}

// VirtualPathSeparator is used to delimit components in virtual paths.
const VirtualPathSeparator = "::"
