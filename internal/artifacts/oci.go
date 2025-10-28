package artifacts

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// OCIManifest represents an OCI image manifest (OCI Image Spec v1)
type OCIManifest struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Config        OCIDescriptor   `json:"config"`
	Layers        []OCIDescriptor `json:"layers"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

// OCIDescriptor describes a content addressable blob
type OCIDescriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// OCIIndex represents an OCI image index (for multi-arch images)
type OCIIndex struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Manifests     []OCIDescriptor `json:"manifests"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

// OCIConfig represents the image configuration
type OCIConfig struct {
	Created      time.Time       `json:"created"`
	Architecture string          `json:"architecture"`
	OS           string          `json:"os"`
	Config       OCIImageConfig  `json:"config"`
	RootFS       OCIRootFS       `json:"rootfs"`
	History      []OCIHistory    `json:"history"`
}

// OCIImageConfig contains image runtime configuration
type OCIImageConfig struct {
	User         string            `json:"User,omitempty"`
	ExposedPorts map[string]struct{} `json:"ExposedPorts,omitempty"`
	Env          []string          `json:"Env,omitempty"`
	Entrypoint   []string          `json:"Entrypoint,omitempty"`
	Cmd          []string          `json:"Cmd,omitempty"`
	Volumes      map[string]struct{} `json:"Volumes,omitempty"`
	WorkingDir   string            `json:"WorkingDir,omitempty"`
	Labels       map[string]string `json:"Labels,omitempty"`
}

// OCIRootFS describes the root filesystem
type OCIRootFS struct {
	Type    string   `json:"type"`
	DiffIDs []string `json:"diff_ids"`
}

// OCIHistory records the history of each layer
type OCIHistory struct {
	Created    time.Time `json:"created"`
	CreatedBy  string    `json:"created_by"`
	Author     string    `json:"author,omitempty"`
	Comment    string    `json:"comment,omitempty"`
	EmptyLayer bool      `json:"empty_layer,omitempty"`
}

// LayerContext provides rich context about a container layer
type LayerContext struct {
	Digest       string    // sha256:abc123...
	Index        int       // Layer 5 of 12
	TotalLayers  int       // Total number of layers
	Size         int64     // Layer size in bytes
	CreatedBy    string    // Dockerfile command that created this layer
	Created      time.Time // Layer creation timestamp
	ParentDigest string    // Previous layer digest
	Architecture string    // e.g., "amd64", "arm64"
	OS           string    // e.g., "linux", "windows"
}

// ParseOCIManifest reads and parses an OCI image manifest from a file
func ParseOCIManifest(path string) (*OCIManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	var manifest OCIManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse manifest JSON: %w", err)
	}

	// Validate schema version
	if manifest.SchemaVersion != 2 {
		return nil, fmt.Errorf("unsupported schema version: %d", manifest.SchemaVersion)
	}

	return &manifest, nil
}

// ParseOCIIndex reads and parses an OCI image index from a file
func ParseOCIIndex(path string) (*OCIIndex, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read index: %w", err)
	}

	var index OCIIndex
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, fmt.Errorf("failed to parse index JSON: %w", err)
	}

	return &index, nil
}

// ParseOCIConfig reads and parses an OCI image config from a file
func ParseOCIConfig(path string) (*OCIConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var config OCIConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config JSON: %w", err)
	}

	return &config, nil
}

// IsOCIImage checks if a directory contains an OCI image layout
func IsOCIImage(dir string) bool {
	// Check for oci-layout file (OCI spec marker)
	layoutPath := filepath.Join(dir, "oci-layout")
	if _, err := os.Stat(layoutPath); err == nil {
		return true
	}

	// Check for index.json (OCI index)
	indexPath := filepath.Join(dir, "index.json")
	if _, err := os.Stat(indexPath); err == nil {
		return true
	}

	return false
}

// BuildLayerContext extracts rich context from image config for a specific layer
func BuildLayerContext(config *OCIConfig, layerIndex int, layerDigest string, layerSize int64) LayerContext {
	ctx := LayerContext{
		Digest:       layerDigest,
		Index:        layerIndex,
		TotalLayers:  len(config.RootFS.DiffIDs),
		Size:         layerSize,
		Architecture: config.Architecture,
		OS:           config.OS,
	}

	// Match layer index to history entry
	// Note: History includes empty layers, so we need to count non-empty layers
	if layerIndex >= 0 && layerIndex < len(config.History) {
		historyIndex := 0
		for i, h := range config.History {
			if !h.EmptyLayer {
				if historyIndex == layerIndex {
					ctx.CreatedBy = h.CreatedBy
					ctx.Created = h.Created
					break
				}
				historyIndex++
			} else if i == layerIndex {
				// This is an empty layer at the exact index
				ctx.CreatedBy = h.CreatedBy
				ctx.Created = h.Created
				break
			}
		}
	}

	// Set parent digest (previous layer)
	if layerIndex > 0 && layerIndex <= len(config.RootFS.DiffIDs) {
		ctx.ParentDigest = config.RootFS.DiffIDs[layerIndex-1]
	}

	return ctx
}

// DetectManifestFormat determines if a file is Docker or OCI format
func DetectManifestFormat(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	// Try to parse as generic manifest to check mediaType
	var generic struct {
		MediaType string `json:"mediaType"`
		SchemaVersion int `json:"schemaVersion"`
	}

	if err := json.Unmarshal(data, &generic); err != nil {
		return "", fmt.Errorf("failed to parse manifest: %w", err)
	}

	// OCI media types
	if generic.MediaType == "application/vnd.oci.image.manifest.v1+json" {
		return "oci", nil
	}
	if generic.MediaType == "application/vnd.oci.image.index.v1+json" {
		return "oci-index", nil
	}

	// Docker media types
	if generic.MediaType == "application/vnd.docker.distribution.manifest.v2+json" {
		return "docker-v2", nil
	}
	if generic.MediaType == "application/vnd.docker.distribution.manifest.list.v2+json" {
		return "docker-manifest-list", nil
	}

	// Fall back to schema version
	if generic.SchemaVersion == 2 {
		return "docker-v2", nil
	}

	return "unknown", nil
}
