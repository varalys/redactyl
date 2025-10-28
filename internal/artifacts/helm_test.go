package artifacts

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsHelmChart(t *testing.T) {
	t.Run("directory with Chart.yaml", func(t *testing.T) {
		tmpDir := t.TempDir()
		chartPath := filepath.Join(tmpDir, "Chart.yaml")
		require.NoError(t, os.WriteFile(chartPath, []byte("name: test"), 0644))

		assert.True(t, IsHelmChart(tmpDir))
	})

	t.Run(".tgz archive", func(t *testing.T) {
		tmpDir := t.TempDir()
		chartPath := filepath.Join(tmpDir, "mychart.tgz")
		require.NoError(t, os.WriteFile(chartPath, []byte("fake"), 0644))

		assert.True(t, IsHelmChart(chartPath))
	})

	t.Run("not a helm chart", func(t *testing.T) {
		tmpDir := t.TempDir()
		assert.False(t, IsHelmChart(tmpDir))
	})
}

func TestParseChartYAML(t *testing.T) {
	chartYAML := `
apiVersion: v2
name: my-app
version: 1.2.3
appVersion: "2.0.1"
description: A Helm chart for Kubernetes
type: application
keywords:
  - web
  - app
maintainers:
  - name: John Doe
    email: john@example.com
`

	tmpDir := t.TempDir()
	chartPath := filepath.Join(tmpDir, "Chart.yaml")
	require.NoError(t, os.WriteFile(chartPath, []byte(chartYAML), 0644))

	chart, err := ParseChartYAML(chartPath)
	require.NoError(t, err)
	assert.Equal(t, "v2", chart.APIVersion)
	assert.Equal(t, "my-app", chart.Name)
	assert.Equal(t, "1.2.3", chart.Version)
	assert.Equal(t, "2.0.1", chart.AppVersion)
	assert.Equal(t, "application", chart.Type)
	assert.Len(t, chart.Keywords, 2)
	assert.Len(t, chart.Maintainers, 1)
	assert.Equal(t, "John Doe", chart.Maintainers[0].Name)
}

func TestParseValuesYAML(t *testing.T) {
	valuesYAML := `
replicaCount: 3
image:
  repository: nginx
  tag: "1.19"
  pullPolicy: IfNotPresent
service:
  type: ClusterIP
  port: 80
`

	tmpDir := t.TempDir()
	valuesPath := filepath.Join(tmpDir, "values.yaml")
	require.NoError(t, os.WriteFile(valuesPath, []byte(valuesYAML), 0644))

	values, err := ParseValuesYAML(valuesPath)
	require.NoError(t, err)
	assert.NotNil(t, values["replicaCount"])
	assert.NotNil(t, values["image"])

	// The exact types depend on YAML parsing, just verify structure exists
	assert.Contains(t, values, "replicaCount")
	assert.Contains(t, values, "image")
	assert.Contains(t, values, "service")
}

func TestScanHelmDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a mock Helm chart structure
	chartDir := filepath.Join(tmpDir, "my-chart")
	require.NoError(t, os.MkdirAll(chartDir, 0755))

	// Create Chart.yaml
	chartYAML := `apiVersion: v2
name: my-chart
version: 1.0.0`
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte(chartYAML), 0644))

	// Create values.yaml with a secret
	valuesYAML := `database:
  password: "token = ghp_ABCDEFGHIJKLMNOPQRST1234567890ab"`
	require.NoError(t, os.WriteFile(filepath.Join(chartDir, "values.yaml"), []byte(valuesYAML), 0644))

	// Create templates directory with a deployment
	templatesDir := filepath.Join(chartDir, "templates")
	require.NoError(t, os.MkdirAll(templatesDir, 0755))

	deploymentYAML := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Chart.Name }}
spec:
  template:
    spec:
      containers:
      - name: app
        env:
        - name: SECRET
          value: "api_key = abc123def456abc123def456abc12"`
	require.NoError(t, os.WriteFile(filepath.Join(templatesDir, "deployment.yaml"), []byte(deploymentYAML), 0644))

	// Scan the chart
	var emissions []struct {
		path string
		data string
	}
	limits := Limits{MaxArchiveBytes: 1024 * 1024}
	err := ScanHelmChartsWithFilter(tmpDir, limits, nil, func(path string, data []byte) {
		emissions = append(emissions, struct {
			path string
			data string
		}{path, string(data)})
	})

	require.NoError(t, err)
	assert.NotEmpty(t, emissions, "Expected to find files in Helm chart")

	// Check that we scanned values.yaml
	foundValues := false
	foundDeployment := false
	for _, e := range emissions {
		if contains(e.path, "values.yaml") {
			foundValues = true
			assert.Contains(t, e.data, "password")
		}
		if contains(e.path, "deployment.yaml") {
			foundDeployment = true
			assert.Contains(t, e.data, "SECRET")
		}
	}

	assert.True(t, foundValues, "Expected to scan values.yaml")
	assert.True(t, foundDeployment, "Expected to scan deployment.yaml")
}

func TestScanHelmArchive(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a .tgz Helm chart archive
	chartPath := filepath.Join(tmpDir, "my-chart.tgz")
	f, err := os.Create(chartPath)
	require.NoError(t, err)
	defer f.Close()

	gzw := gzip.NewWriter(f)
	defer gzw.Close()
	tw := tar.NewWriter(gzw)
	defer tw.Close()

	// Add Chart.yaml
	chartYAML := []byte("apiVersion: v2\nname: my-chart\nversion: 1.0.0")
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: "my-chart/Chart.yaml",
		Size: int64(len(chartYAML)),
		Mode: 0644,
	}))
	_, err = tw.Write(chartYAML)
	require.NoError(t, err)

	// Add values.yaml with a secret
	valuesYAML := []byte("password: token = ghp_ABCDEFGHIJKLMNOPQRST1234567890ab")
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: "my-chart/values.yaml",
		Size: int64(len(valuesYAML)),
		Mode: 0644,
	}))
	_, err = tw.Write(valuesYAML)
	require.NoError(t, err)

	// Add a template
	templateYAML := []byte("apiVersion: v1\nkind: Secret\ndata:\n  key: api_key = abc123def456abc123def456abc12")
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: "my-chart/templates/secret.yaml",
		Size: int64(len(templateYAML)),
		Mode: 0644,
	}))
	_, err = tw.Write(templateYAML)
	require.NoError(t, err)

	tw.Close()
	gzw.Close()
	f.Close()

	// Scan the archive
	var emissions []struct {
		path string
		data string
	}
	limits := Limits{MaxArchiveBytes: 1024 * 1024}
	err = ScanHelmChartsWithFilter(tmpDir, limits, nil, func(path string, data []byte) {
		emissions = append(emissions, struct {
			path string
			data string
		}{path, string(data)})
	})

	require.NoError(t, err)
	assert.NotEmpty(t, emissions, "Expected to find files in Helm archive")

	// Verify virtual paths
	foundValues := false
	foundTemplate := false
	for _, e := range emissions {
		if contains(e.path, "::") && contains(e.path, "values.yaml") {
			foundValues = true
			assert.Contains(t, e.data, "password")
		}
		if contains(e.path, "::") && contains(e.path, "secret.yaml") {
			foundTemplate = true
			assert.Contains(t, e.data, "api_key")
		}
	}

	assert.True(t, foundValues, "Expected to scan values.yaml from archive")
	assert.True(t, foundTemplate, "Expected to scan template from archive")
}

func TestShouldScanHelmFile(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		expected bool
	}{
		{"values.yaml", "my-chart/values.yaml", true},
		{"Chart.yaml", "my-chart/Chart.yaml", true},
		{"template YAML", "my-chart/templates/deployment.yaml", true},
		{"secret template", "my-chart/templates/secret.yaml", true},
		{"configmap", "my-chart/templates/configmap.yaml", true},
		{"README", "my-chart/README.md", false},
		{"helper", "my-chart/templates/_helpers.tpl", false},
		{"random file", "my-chart/random.txt", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldScanHelmFile(tt.filename)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractChartMetadata(t *testing.T) {
	chart := &HelmChart{
		Name:        "my-app",
		Version:     "1.2.3",
		AppVersion:  "2.0.1",
		Description: "A sample application",
	}

	metadata := ExtractChartMetadata(chart)
	assert.Equal(t, "my-app", metadata["chart_name"])
	assert.Equal(t, "1.2.3", metadata["chart_version"])
	assert.Equal(t, "2.0.1", metadata["app_version"])
	assert.Equal(t, "A sample application", metadata["description"])
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
		len(s) > len(substr)+1 && s[1:len(substr)+1] == substr ||
		len(s) > len(substr)*2 && s[len(s)/2-len(substr)/2:len(s)/2+len(substr)/2+1] == substr ||
		findInString(s, substr)))
}

func findInString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
