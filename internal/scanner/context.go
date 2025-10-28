package scanner

import "strings"

// ParseVirtualPath splits a virtual path into its components.
// Example: "image.tar::layer-abc::etc/app.yaml" -> ["image.tar", "layer-abc", "etc/app.yaml"]
func ParseVirtualPath(path string) []string {
	if path == "" {
		return nil
	}
	return strings.Split(path, VirtualPathSeparator)
}

// BuildVirtualPath constructs a virtual path from components.
// Example: BuildVirtualPath("image.tar", "layer-abc", "etc/app.yaml") -> "image.tar::layer-abc::etc/app.yaml"
func BuildVirtualPath(components ...string) string {
	return strings.Join(components, VirtualPathSeparator)
}

// IsVirtualPath checks if a path contains virtual path separators.
func IsVirtualPath(path string) bool {
	return strings.Contains(path, VirtualPathSeparator)
}

// GetArtifactRoot extracts the root artifact from a virtual path.
// Example: "image.tar::layer-abc::etc/app.yaml" -> "image.tar"
func GetArtifactRoot(path string) string {
	parts := ParseVirtualPath(path)
	if len(parts) > 0 {
		return parts[0]
	}
	return path
}

// GetDepth returns the nesting depth of a virtual path.
// Example: "image.tar::layer-abc::etc/app.yaml" -> 3
func GetDepth(path string) int {
	if path == "" {
		return 0
	}
	return len(ParseVirtualPath(path))
}
