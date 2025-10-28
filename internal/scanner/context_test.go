package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseVirtualPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected []string
	}{
		{
			name:     "simple path",
			path:     "file.txt",
			expected: []string{"file.txt"},
		},
		{
			name:     "archive path",
			path:     "archive.zip::file.txt",
			expected: []string{"archive.zip", "file.txt"},
		},
		{
			name:     "nested archive",
			path:     "outer.zip::inner.tar::file.txt",
			expected: []string{"outer.zip", "inner.tar", "file.txt"},
		},
		{
			name:     "container layer path",
			path:     "image.tar::layer-sha256:abc123::etc/config.yaml",
			expected: []string{"image.tar", "layer-sha256:abc123", "etc/config.yaml"},
		},
		{
			name:     "empty path",
			path:     "",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseVirtualPath(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildVirtualPath(t *testing.T) {
	tests := []struct {
		name       string
		components []string
		expected   string
	}{
		{
			name:       "single component",
			components: []string{"file.txt"},
			expected:   "file.txt",
		},
		{
			name:       "two components",
			components: []string{"archive.zip", "file.txt"},
			expected:   "archive.zip::file.txt",
		},
		{
			name:       "three components",
			components: []string{"outer.zip", "inner.tar", "file.txt"},
			expected:   "outer.zip::inner.tar::file.txt",
		},
		{
			name:       "container path",
			components: []string{"image.tar", "layer-sha256:abc123", "etc/config.yaml"},
			expected:   "image.tar::layer-sha256:abc123::etc/config.yaml",
		},
		{
			name:       "no components",
			components: []string{},
			expected:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildVirtualPath(tt.components...)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsVirtualPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "simple path",
			path:     "file.txt",
			expected: false,
		},
		{
			name:     "virtual path",
			path:     "archive.zip::file.txt",
			expected: true,
		},
		{
			name:     "nested virtual path",
			path:     "outer.zip::inner.tar::file.txt",
			expected: true,
		},
		{
			name:     "empty path",
			path:     "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsVirtualPath(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetArtifactRoot(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "simple path",
			path:     "file.txt",
			expected: "file.txt",
		},
		{
			name:     "archive path",
			path:     "archive.zip::file.txt",
			expected: "archive.zip",
		},
		{
			name:     "nested path",
			path:     "outer.zip::inner.tar::file.txt",
			expected: "outer.zip",
		},
		{
			name:     "container path",
			path:     "image.tar::layer-sha256:abc123::etc/config.yaml",
			expected: "image.tar",
		},
		{
			name:     "empty path",
			path:     "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetArtifactRoot(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetDepth(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected int
	}{
		{
			name:     "empty path",
			path:     "",
			expected: 0,
		},
		{
			name:     "simple path",
			path:     "file.txt",
			expected: 1,
		},
		{
			name:     "archive path",
			path:     "archive.zip::file.txt",
			expected: 2,
		},
		{
			name:     "nested path",
			path:     "outer.zip::inner.tar::file.txt",
			expected: 3,
		},
		{
			name:     "deeply nested",
			path:     "a::b::c::d::e",
			expected: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetDepth(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}
