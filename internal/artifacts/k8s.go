package artifacts

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/redactyl/redactyl/internal/ignore"
	yaml "gopkg.in/yaml.v3"
)

// K8sResource represents a generic Kubernetes resource
type K8sResource struct {
	APIVersion string                 `yaml:"apiVersion"`
	Kind       string                 `yaml:"kind"`
	Metadata   K8sMetadata            `yaml:"metadata"`
	Data       map[string]interface{} `yaml:"data,omitempty"`
	StringData map[string]string      `yaml:"stringData,omitempty"`
	Spec       map[string]interface{} `yaml:"spec,omitempty"`
}

// K8sMetadata represents Kubernetes metadata
type K8sMetadata struct {
	Name        string            `yaml:"name"`
	Namespace   string            `yaml:"namespace,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty"`
	Annotations map[string]string `yaml:"annotations,omitempty"`
}

// IsK8sManifest checks if a file appears to be a Kubernetes manifest
func IsK8sManifest(path string) bool {
	if !strings.HasSuffix(strings.ToLower(path), ".yaml") &&
		!strings.HasSuffix(strings.ToLower(path), ".yml") {
		return false
	}

	// Check for common k8s patterns in filename
	lower := strings.ToLower(filepath.Base(path))
	k8sPatterns := []string{
		"deployment", "service", "configmap", "secret",
		"ingress", "pod", "statefulset", "daemonset",
		"job", "cronjob", "pvc", "pv",
	}

	for _, pattern := range k8sPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	// Try to parse as YAML and check for apiVersion/kind
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	var resource K8sResource
	if err := yaml.Unmarshal(data, &resource); err != nil {
		return false
	}

	return resource.APIVersion != "" && resource.Kind != ""
}

// ParseK8sResource parses a Kubernetes resource from a file
func ParseK8sResource(path string) (*K8sResource, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var resource K8sResource
	if err := yaml.Unmarshal(data, &resource); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	if resource.APIVersion == "" || resource.Kind == "" {
		return nil, fmt.Errorf("not a valid Kubernetes resource (missing apiVersion or kind)")
	}

	return &resource, nil
}

// ParseK8sResources parses multiple Kubernetes resources from a multi-document YAML file
func ParseK8sResources(path string) ([]*K8sResource, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var resources []*K8sResource

	for {
		var resource K8sResource
		err := decoder.Decode(&resource)
		if err == io.EOF {
			break
		}
		if err != nil {
			// Skip invalid documents
			continue
		}

		// Only include valid K8s resources
		if resource.APIVersion != "" && resource.Kind != "" {
			resources = append(resources, &resource)
		}
	}

	return resources, nil
}

// ScanK8sManifests walks the root directory and scans Kubernetes manifests for secrets
func ScanK8sManifests(root string, limits Limits, emit func(path string, data []byte)) error {
	return ScanK8sManifestsWithFilter(root, limits, nil, emit)
}

// ScanK8sManifestsWithFilter is like ScanK8sManifests but with an optional path filter
func ScanK8sManifestsWithFilter(root string, limits Limits, allow PathAllowFunc, emit func(path string, data []byte)) error {
	ign, _ := ignore.Load(filepath.Join(root, ".redactylignore"))

	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() {
			return nil
		}

		rel, _ := filepath.Rel(root, p)
		if ign.Match(rel) {
			return nil
		}

		if allow != nil && !allow(rel) {
			return nil
		}

		// Check if this looks like a K8s manifest
		if !isK8sManifestFile(rel) {
			return nil
		}

		// Read and emit the file
		data, err := os.ReadFile(p)
		if err != nil {
			return nil // Skip on error
		}

		// Verify it's actually a K8s resource
		if containsK8sResource(data) {
			emit(rel, data)
		}

		return nil
	})
}

// isK8sManifestFile checks if a filename suggests it might be a K8s manifest
func isK8sManifestFile(path string) bool {
	lower := strings.ToLower(path)

	// Must be YAML
	if !strings.HasSuffix(lower, ".yaml") && !strings.HasSuffix(lower, ".yml") {
		return false
	}

	// Check for K8s-related directories
	k8sDirs := []string{
		"k8s/", "kubernetes/", "manifests/", ".k8s/",
		"deploy/", "deployment/", "kube/",
	}
	for _, dir := range k8sDirs {
		if strings.Contains(lower, dir) {
			return true
		}
	}

	// Check for K8s-related filenames
	base := filepath.Base(lower)
	k8sPatterns := []string{
		"deployment", "service", "configmap", "secret",
		"ingress", "pod", "statefulset", "daemonset",
		"job", "cronjob", "pvc", "pv", "namespace",
		"rbac", "role", "clusterrole", "serviceaccount",
	}

	for _, pattern := range k8sPatterns {
		if strings.Contains(base, pattern) {
			return true
		}
	}

	return false
}

// containsK8sResource checks if YAML data contains a valid K8s resource
func containsK8sResource(data []byte) bool {
	// Quick check for common K8s fields
	content := string(data)
	return strings.Contains(content, "apiVersion") &&
		strings.Contains(content, "kind") &&
		(strings.Contains(content, "metadata") || strings.Contains(content, "spec"))
}

// IsSensitiveK8sResource checks if a resource type typically contains secrets
func IsSensitiveK8sResource(resource *K8sResource) bool {
	sensitiveKinds := []string{
		"Secret",
		"ConfigMap", // Can contain sensitive data
	}

	for _, kind := range sensitiveKinds {
		if resource.Kind == kind {
			return true
		}
	}

	// Check for secrets in pod specs
	if resource.Kind == "Pod" || resource.Kind == "Deployment" ||
		resource.Kind == "StatefulSet" || resource.Kind == "DaemonSet" ||
		resource.Kind == "Job" || resource.Kind == "CronJob" {
		return true // These can have env vars with secrets
	}

	return false
}

// ExtractK8sMetadata extracts useful metadata from a K8s resource for reporting
func ExtractK8sMetadata(resource *K8sResource) map[string]string {
	metadata := make(map[string]string)

	if resource.Kind != "" {
		metadata["k8s_kind"] = resource.Kind
	}
	if resource.APIVersion != "" {
		metadata["k8s_api_version"] = resource.APIVersion
	}
	if resource.Metadata.Name != "" {
		metadata["k8s_name"] = resource.Metadata.Name
	}
	if resource.Metadata.Namespace != "" {
		metadata["k8s_namespace"] = resource.Metadata.Namespace
	}

	return metadata
}

// FindSecretsInResource searches for likely secret fields in a K8s resource
// Returns paths to fields that might contain secrets
func FindSecretsInResource(resource *K8sResource) []string {
	var secretPaths []string

	// Check Secret resource data fields
	if resource.Kind == "Secret" {
		for key := range resource.Data {
			secretPaths = append(secretPaths, fmt.Sprintf("data.%s", key))
		}
		for key := range resource.StringData {
			secretPaths = append(secretPaths, fmt.Sprintf("stringData.%s", key))
		}
	}

	// Check ConfigMap for potential secrets (common mistake)
	if resource.Kind == "ConfigMap" {
		for key := range resource.Data {
			lower := strings.ToLower(key)
			if strings.Contains(lower, "password") ||
				strings.Contains(lower, "secret") ||
				strings.Contains(lower, "key") ||
				strings.Contains(lower, "token") {
				secretPaths = append(secretPaths, fmt.Sprintf("data.%s", key))
			}
		}
	}

	return secretPaths
}
