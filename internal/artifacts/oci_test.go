package artifacts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseOCIManifest(t *testing.T) {
	manifest := OCIManifest{
		SchemaVersion: 2,
		MediaType:     "application/vnd.oci.image.manifest.v1+json",
		Config: OCIDescriptor{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Digest:    "sha256:abc123",
			Size:      1234,
		},
		Layers: []OCIDescriptor{
			{
				MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
				Digest:    "sha256:layer1",
				Size:      5678,
			},
			{
				MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
				Digest:    "sha256:layer2",
				Size:      91011,
			},
		},
	}

	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "manifest.json")

	data, err := json.Marshal(manifest)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(manifestPath, data, 0644))

	parsed, err := ParseOCIManifest(manifestPath)
	require.NoError(t, err)
	assert.Equal(t, 2, parsed.SchemaVersion)
	assert.Equal(t, "sha256:abc123", parsed.Config.Digest)
	assert.Len(t, parsed.Layers, 2)
	assert.Equal(t, "sha256:layer1", parsed.Layers[0].Digest)
}

func TestParseOCIManifest_InvalidSchema(t *testing.T) {
	manifest := OCIManifest{
		SchemaVersion: 1, // Invalid
		MediaType:     "application/vnd.oci.image.manifest.v1+json",
	}

	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "manifest.json")

	data, err := json.Marshal(manifest)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(manifestPath, data, 0644))

	_, err = ParseOCIManifest(manifestPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported schema version")
}

func TestParseOCIIndex(t *testing.T) {
	index := OCIIndex{
		SchemaVersion: 2,
		MediaType:     "application/vnd.oci.image.index.v1+json",
		Manifests: []OCIDescriptor{
			{
				MediaType: "application/vnd.oci.image.manifest.v1+json",
				Digest:    "sha256:amd64manifest",
				Size:      1234,
				Annotations: map[string]string{
					"org.opencontainers.image.ref.name": "latest-amd64",
				},
			},
			{
				MediaType: "application/vnd.oci.image.manifest.v1+json",
				Digest:    "sha256:arm64manifest",
				Size:      5678,
				Annotations: map[string]string{
					"org.opencontainers.image.ref.name": "latest-arm64",
				},
			},
		},
	}

	tmpDir := t.TempDir()
	indexPath := filepath.Join(tmpDir, "index.json")

	data, err := json.Marshal(index)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(indexPath, data, 0644))

	parsed, err := ParseOCIIndex(indexPath)
	require.NoError(t, err)
	assert.Equal(t, 2, parsed.SchemaVersion)
	assert.Len(t, parsed.Manifests, 2)
	assert.Equal(t, "sha256:amd64manifest", parsed.Manifests[0].Digest)
}

func TestParseOCIConfig(t *testing.T) {
	created := time.Now().UTC()
	config := OCIConfig{
		Created:      created,
		Architecture: "amd64",
		OS:           "linux",
		Config: OCIImageConfig{
			Env: []string{"PATH=/usr/bin"},
			Cmd: []string{"/bin/sh"},
		},
		RootFS: OCIRootFS{
			Type:    "layers",
			DiffIDs: []string{"sha256:layer1", "sha256:layer2"},
		},
		History: []OCIHistory{
			{
				Created:   created,
				CreatedBy: "RUN apt-get update",
			},
			{
				Created:   created,
				CreatedBy: "COPY . /app",
			},
		},
	}

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")

	data, err := json.Marshal(config)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(configPath, data, 0644))

	parsed, err := ParseOCIConfig(configPath)
	require.NoError(t, err)
	assert.Equal(t, "amd64", parsed.Architecture)
	assert.Equal(t, "linux", parsed.OS)
	assert.Len(t, parsed.RootFS.DiffIDs, 2)
	assert.Len(t, parsed.History, 2)
	assert.Equal(t, "RUN apt-get update", parsed.History[0].CreatedBy)
}

func TestIsOCIImage(t *testing.T) {
	t.Run("with oci-layout file", func(t *testing.T) {
		tmpDir := t.TempDir()
		layoutPath := filepath.Join(tmpDir, "oci-layout")
		require.NoError(t, os.WriteFile(layoutPath, []byte(`{"imageLayoutVersion":"1.0.0"}`), 0644))

		assert.True(t, IsOCIImage(tmpDir))
	})

	t.Run("with index.json", func(t *testing.T) {
		tmpDir := t.TempDir()
		indexPath := filepath.Join(tmpDir, "index.json")
		require.NoError(t, os.WriteFile(indexPath, []byte(`{"schemaVersion":2}`), 0644))

		assert.True(t, IsOCIImage(tmpDir))
	})

	t.Run("not an OCI image", func(t *testing.T) {
		tmpDir := t.TempDir()
		assert.False(t, IsOCIImage(tmpDir))
	})
}

func TestBuildLayerContext(t *testing.T) {
	created := time.Now().UTC()
	config := &OCIConfig{
		Architecture: "amd64",
		OS:           "linux",
		RootFS: OCIRootFS{
			Type:    "layers",
			DiffIDs: []string{"sha256:layer0", "sha256:layer1", "sha256:layer2"},
		},
		History: []OCIHistory{
			{
				Created:   created,
				CreatedBy: "FROM alpine:latest",
			},
			{
				Created:   created.Add(time.Minute),
				CreatedBy: "RUN apk add --no-cache git",
			},
			{
				Created:   created.Add(2 * time.Minute),
				CreatedBy: "COPY . /app",
			},
		},
	}

	ctx := BuildLayerContext(config, 1, "sha256:layer1", 12345)

	assert.Equal(t, "sha256:layer1", ctx.Digest)
	assert.Equal(t, 1, ctx.Index)
	assert.Equal(t, 3, ctx.TotalLayers)
	assert.Equal(t, int64(12345), ctx.Size)
	assert.Equal(t, "RUN apk add --no-cache git", ctx.CreatedBy)
	assert.Equal(t, "amd64", ctx.Architecture)
	assert.Equal(t, "linux", ctx.OS)
	assert.Equal(t, "sha256:layer0", ctx.ParentDigest)
}

func TestDetectManifestFormat(t *testing.T) {
	tests := []struct {
		name     string
		manifest interface{}
		expected string
	}{
		{
			name: "OCI manifest",
			manifest: map[string]interface{}{
				"schemaVersion": 2,
				"mediaType":     "application/vnd.oci.image.manifest.v1+json",
			},
			expected: "oci",
		},
		{
			name: "OCI index",
			manifest: map[string]interface{}{
				"schemaVersion": 2,
				"mediaType":     "application/vnd.oci.image.index.v1+json",
			},
			expected: "oci-index",
		},
		{
			name: "Docker v2 manifest",
			manifest: map[string]interface{}{
				"schemaVersion": 2,
				"mediaType":     "application/vnd.docker.distribution.manifest.v2+json",
			},
			expected: "docker-v2",
		},
		{
			name: "Docker manifest list",
			manifest: map[string]interface{}{
				"schemaVersion": 2,
				"mediaType":     "application/vnd.docker.distribution.manifest.list.v2+json",
			},
			expected: "docker-manifest-list",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			manifestPath := filepath.Join(tmpDir, "manifest.json")

			data, err := json.Marshal(tt.manifest)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(manifestPath, data, 0644))

			format, err := DetectManifestFormat(manifestPath)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, format)
		})
	}
}
