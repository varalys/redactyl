package artifacts

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/redactyl/redactyl/internal/ignore"
	yaml "gopkg.in/yaml.v3"
)

// HelmChart represents a Helm chart metadata
type HelmChart struct {
	APIVersion   string            `yaml:"apiVersion"`
	Name         string            `yaml:"name"`
	Version      string            `yaml:"version"`
	KubeVersion  string            `yaml:"kubeVersion,omitempty"`
	Description  string            `yaml:"description,omitempty"`
	Type         string            `yaml:"type,omitempty"`
	Keywords     []string          `yaml:"keywords,omitempty"`
	Home         string            `yaml:"home,omitempty"`
	Sources      []string          `yaml:"sources,omitempty"`
	Dependencies []HelmDependency  `yaml:"dependencies,omitempty"`
	Maintainers  []HelmMaintainer  `yaml:"maintainers,omitempty"`
	Icon         string            `yaml:"icon,omitempty"`
	AppVersion   string            `yaml:"appVersion,omitempty"`
	Deprecated   bool              `yaml:"deprecated,omitempty"`
	Annotations  map[string]string `yaml:"annotations,omitempty"`
}

// HelmDependency represents a chart dependency
type HelmDependency struct {
	Name       string   `yaml:"name"`
	Version    string   `yaml:"version"`
	Repository string   `yaml:"repository"`
	Condition  string   `yaml:"condition,omitempty"`
	Tags       []string `yaml:"tags,omitempty"`
	Enabled    bool     `yaml:"enabled,omitempty"`
	Alias      string   `yaml:"alias,omitempty"`
}

// HelmMaintainer represents a chart maintainer
type HelmMaintainer struct {
	Name  string `yaml:"name"`
	Email string `yaml:"email,omitempty"`
	URL   string `yaml:"url,omitempty"`
}

// HelmValues represents parsed values.yaml
type HelmValues map[string]interface{}

// IsHelmChart checks if a path appears to be a Helm chart
// Looks for Chart.yaml in the root or as a .tgz archive
func IsHelmChart(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	// Check if it's a .tgz archive
	if !info.IsDir() && strings.HasSuffix(strings.ToLower(path), ".tgz") {
		return true
	}

	// Check if it's a directory with Chart.yaml
	if info.IsDir() {
		chartPath := filepath.Join(path, "Chart.yaml")
		if _, err := os.Stat(chartPath); err == nil {
			return true
		}
	}

	return false
}

// ParseChartYAML reads and parses a Chart.yaml file
func ParseChartYAML(path string) (*HelmChart, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read Chart.yaml: %w", err)
	}

	var chart HelmChart
	if err := yaml.Unmarshal(data, &chart); err != nil {
		return nil, fmt.Errorf("failed to parse Chart.yaml: %w", err)
	}

	return &chart, nil
}

// ParseValuesYAML reads and parses a values.yaml file
func ParseValuesYAML(path string) (HelmValues, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read values.yaml: %w", err)
	}

	var values HelmValues
	if err := yaml.Unmarshal(data, &values); err != nil {
		return nil, fmt.Errorf("failed to parse values.yaml: %w", err)
	}

	return values, nil
}

// ScanHelmCharts walks the root directory and scans Helm charts for secrets
// It processes both unpacked chart directories and .tgz archives
func ScanHelmCharts(root string, limits Limits, emit func(path string, data []byte)) error {
	return ScanHelmChartsWithFilter(root, limits, nil, emit)
}

// ScanHelmChartsWithFilter is like ScanHelmCharts but with an optional path filter
func ScanHelmChartsWithFilter(root string, limits Limits, allow PathAllowFunc, emit func(path string, data []byte)) error {
	ign, _ := ignore.Load(filepath.Join(root, ".redactylignore"))

	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		rel, _ := filepath.Rel(root, p)
		if ign.Match(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if allow != nil && !allow(rel) {
			return nil
		}

		// Check for .tgz Helm chart archives
		if !d.IsDir() && strings.HasSuffix(strings.ToLower(rel), ".tgz") {
			return scanHelmArchive(p, rel, limits, emit)
		}

		// Check for unpacked Helm chart directories (contain Chart.yaml)
		if d.IsDir() {
			chartPath := filepath.Join(p, "Chart.yaml")
			if _, err := os.Stat(chartPath); err == nil {
				return scanHelmDirectory(p, rel, limits, emit)
			}
		}

		return nil
	})
}

// scanHelmArchive scans a .tgz Helm chart archive
func scanHelmArchive(archivePath, relPath string, limits Limits, emit func(path string, data []byte)) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return nil // Skip on error
	}
	defer safeClose(f)

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return nil // Not a valid gzip
	}
	defer safeClose(gzr)

	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil
		}

		// Skip directories
		if hdr.FileInfo().IsDir() {
			continue
		}

		name := hdr.Name

		// Scan interesting files in the chart
		if shouldScanHelmFile(name) {
			// Read file content
			data, err := io.ReadAll(io.LimitReader(tr, limits.MaxArchiveBytes))
			if err != nil {
				continue
			}

			// Build virtual path
			vpath := relPath + "::" + name
			emit(vpath, data)
		}
	}

	return nil
}

// scanHelmDirectory scans an unpacked Helm chart directory
func scanHelmDirectory(chartDir, relPath string, limits Limits, emit func(path string, data []byte)) error {
	// Scan templates directory
	templatesDir := filepath.Join(chartDir, "templates")
	if info, err := os.Stat(templatesDir); err == nil && info.IsDir() {
		_ = filepath.WalkDir(templatesDir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}

			// Only scan YAML files in templates
			if !strings.HasSuffix(strings.ToLower(p), ".yaml") && !strings.HasSuffix(strings.ToLower(p), ".yml") {
				return nil
			}

			data, err := os.ReadFile(p)
			if err != nil {
				return nil
			}

			rel, _ := filepath.Rel(chartDir, p)
			vpath := relPath + "::" + rel
			emit(vpath, data)
			return nil
		})
	}

	// Scan values files
	for _, valuesFile := range []string{"values.yaml", "values.yml"} {
		valuesPath := filepath.Join(chartDir, valuesFile)
		if data, err := os.ReadFile(valuesPath); err == nil {
			vpath := relPath + "::" + valuesFile
			emit(vpath, data)
		}
	}

	// Scan Chart.yaml
	chartYAML := filepath.Join(chartDir, "Chart.yaml")
	if data, err := os.ReadFile(chartYAML); err == nil {
		vpath := relPath + "::" + "Chart.yaml"
		emit(vpath, data)
	}

	return nil
}

// shouldScanHelmFile determines if a file in a Helm chart should be scanned
func shouldScanHelmFile(name string) bool {
	lower := strings.ToLower(name)

	// Always scan values files
	if strings.HasSuffix(lower, "/values.yaml") || strings.HasSuffix(lower, "/values.yml") {
		return true
	}

	// Always scan Chart.yaml
	if strings.HasSuffix(lower, "/chart.yaml") || strings.HasSuffix(lower, "/chart.yml") {
		return true
	}

	// Scan template files
	if strings.Contains(lower, "/templates/") {
		if strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") {
			return true
		}
	}

	// Scan secrets and configmaps
	if strings.Contains(lower, "secret") || strings.Contains(lower, "configmap") {
		if strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") {
			return true
		}
	}

	return false
}

// ExtractChartMetadata extracts useful metadata from a Helm chart for reporting
func ExtractChartMetadata(chart *HelmChart) map[string]string {
	metadata := make(map[string]string)

	if chart.Name != "" {
		metadata["chart_name"] = chart.Name
	}
	if chart.Version != "" {
		metadata["chart_version"] = chart.Version
	}
	if chart.AppVersion != "" {
		metadata["app_version"] = chart.AppVersion
	}
	if chart.Description != "" {
		metadata["description"] = chart.Description
	}

	return metadata
}
