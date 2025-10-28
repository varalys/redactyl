package redactyl

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLI_Helm_Chart_Directory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a mock Helm chart structure
	chartDir := filepath.Join(tmpDir, "my-chart")
	if err := os.MkdirAll(chartDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create Chart.yaml
	chartYAML := `apiVersion: v2
name: my-chart
version: 1.0.0`
	if err := os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte(chartYAML), 0644); err != nil {
		t.Fatal(err)
	}

	// Create values.yaml with a secret (medium entropy for testing)
	valuesYAML := `database:
  password: "token = abc123def456abc123def456abc12"`
	if err := os.WriteFile(filepath.Join(chartDir, "values.yaml"), []byte(valuesYAML), 0644); err != nil {
		t.Fatal(err)
	}

	// Create templates directory with a deployment
	templatesDir := filepath.Join(chartDir, "templates")
	if err := os.MkdirAll(templatesDir, 0755); err != nil {
		t.Fatal(err)
	}

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
	if err := os.WriteFile(filepath.Join(templatesDir, "deployment.yaml"), []byte(deploymentYAML), 0644); err != nil {
		t.Fatal(err)
	}

	// Run scan with --helm flag
	cmd := exec.Command("go", "run", ".", "scan", "--json", "--helm", "--fail-on", "high", "-p", tmpDir)
	cmd.Dir = filepath.Clean(filepath.Join("..", ".."))
	output, err := cmd.Output()
	if err != nil {
		t.Logf("command failed: %v, output: %s", err, string(output))
	}

	// Parse findings
	var findings []map[string]interface{}
	if err := json.Unmarshal(output, &findings); err != nil {
		t.Fatalf("failed to parse JSON: %v\nOutput: %s", err, string(output))
	}

	// Should find secrets in Helm chart
	if len(findings) == 0 {
		t.Fatal("expected to find secrets in Helm chart")
	}

	// Verify virtual paths contain Helm chart structure
	foundChartFile := false
	for _, f := range findings {
		path, _ := f["path"].(string)
		if path != "" && (strings.Contains(path, "my-chart") || strings.Contains(path, "values.yaml") || strings.Contains(path, "deployment.yaml")) {
			foundChartFile = true
			break
		}
	}

	if !foundChartFile {
		t.Error("expected to find Helm chart files in scan results")
	}
}

func TestCLI_Helm_Chart_Archive(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a .tgz Helm chart archive
	chartPath := filepath.Join(tmpDir, "my-chart.tgz")
	f, err := os.Create(chartPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	gzw := gzip.NewWriter(f)
	defer gzw.Close()
	tw := tar.NewWriter(gzw)
	defer tw.Close()

	// Add Chart.yaml
	chartYAML := []byte("apiVersion: v2\nname: my-chart\nversion: 1.0.0")
	if err := tw.WriteHeader(&tar.Header{
		Name: "my-chart/Chart.yaml",
		Size: int64(len(chartYAML)),
		Mode: 0644,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(chartYAML); err != nil {
		t.Fatal(err)
	}

	// Add values.yaml with a secret (medium entropy)
	valuesYAML := []byte("password: token = abc123def456abc123def456abc12")
	if err := tw.WriteHeader(&tar.Header{
		Name: "my-chart/values.yaml",
		Size: int64(len(valuesYAML)),
		Mode: 0644,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(valuesYAML); err != nil {
		t.Fatal(err)
	}

	tw.Close()
	gzw.Close()
	f.Close()

	// Run scan with --helm flag
	cmd := exec.Command("go", "run", ".", "scan", "--json", "--helm", "--fail-on", "high", "-p", tmpDir)
	cmd.Dir = filepath.Clean(filepath.Join("..", ".."))
	output, err := cmd.Output()
	if err != nil {
		t.Logf("command failed: %v, output: %s", err, string(output))
	}

	// Parse findings
	var findings []map[string]interface{}
	if err := json.Unmarshal(output, &findings); err != nil {
		t.Fatalf("failed to parse JSON: %v\nOutput: %s", err, string(output))
	}

	// Should find secrets in Helm archive
	if len(findings) == 0 {
		t.Fatal("expected to find secrets in Helm chart archive")
	}

	// Verify virtual paths show nested structure (archive::file)
	foundNestedPath := false
	for _, f := range findings {
		path, _ := f["path"].(string)
		if path != "" && strings.Contains(path, "::") {
			foundNestedPath = true
			break
		}
	}

	if !foundNestedPath {
		t.Error("expected to find nested paths (::) in Helm archive scan results")
	}
}

func TestCLI_K8s_Manifests(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a k8s directory
	k8sDir := filepath.Join(tmpDir, "k8s")
	if err := os.MkdirAll(k8sDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create a Secret manifest with actual secret data (medium entropy)
	secretYAML := `apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
  namespace: default
type: Opaque
stringData:
  database-password: "token = abc123def456abc123def456abc12"
  api-key: "api_key = abc123def456abc123def456abc12"`
	if err := os.WriteFile(filepath.Join(k8sDir, "secret.yaml"), []byte(secretYAML), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a Deployment with env secrets (medium entropy)
	deploymentYAML := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
  namespace: default
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
    spec:
      containers:
      - name: myapp
        image: myapp:latest
        env:
        - name: DB_PASSWORD
          value: "password = abc123def456abc123def456abc12"
        - name: API_TOKEN
          value: "token = abc123def456abc123def456abc12"`
	if err := os.WriteFile(filepath.Join(k8sDir, "deployment.yaml"), []byte(deploymentYAML), 0644); err != nil {
		t.Fatal(err)
	}

	// Run scan with --k8s flag
	cmd := exec.Command("go", "run", ".", "scan", "--json", "--k8s", "--fail-on", "high", "-p", tmpDir)
	cmd.Dir = filepath.Clean(filepath.Join("..", ".."))
	output, err := cmd.Output()
	if err != nil {
		t.Logf("command failed: %v, output: %s", err, string(output))
	}

	// Parse findings
	var findings []map[string]interface{}
	if err := json.Unmarshal(output, &findings); err != nil {
		t.Fatalf("failed to parse JSON: %v\nOutput: %s", err, string(output))
	}

	// Should find secrets in K8s manifests
	if len(findings) == 0 {
		t.Fatal("expected to find secrets in Kubernetes manifests")
	}

	// Verify we scanned K8s files
	foundK8sFile := false
	for _, f := range findings {
		path, _ := f["path"].(string)
		if path != "" && (strings.Contains(path, "secret.yaml") || strings.Contains(path, "deployment.yaml")) {
			foundK8sFile = true
			break
		}
	}

	if !foundK8sFile {
		t.Error("expected to find K8s manifest files in scan results")
	}
}

func TestCLI_Helm_And_K8s_Combined(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a Helm chart
	chartDir := filepath.Join(tmpDir, "helm-charts", "my-app")
	if err := os.MkdirAll(chartDir, 0755); err != nil {
		t.Fatal(err)
	}
	chartYAML := "apiVersion: v2\nname: my-app\nversion: 1.0.0"
	if err := os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte(chartYAML), 0644); err != nil {
		t.Fatal(err)
	}
	valuesYAML := "password: token = abc123def456abc123def456abc12"
	if err := os.WriteFile(filepath.Join(chartDir, "values.yaml"), []byte(valuesYAML), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a K8s manifest
	k8sDir := filepath.Join(tmpDir, "k8s")
	if err := os.MkdirAll(k8sDir, 0755); err != nil {
		t.Fatal(err)
	}
	secretYAML := "apiVersion: v1\nkind: Secret\ndata:\n  key: \"api_key = abc123def456abc123def456abc12\""
	if err := os.WriteFile(filepath.Join(k8sDir, "secret.yaml"), []byte(secretYAML), 0644); err != nil {
		t.Fatal(err)
	}

	// Run scan with both --helm and --k8s flags
	cmd := exec.Command("go", "run", ".", "scan", "--json", "--helm", "--k8s", "--fail-on", "high", "-p", tmpDir)
	cmd.Dir = filepath.Clean(filepath.Join("..", ".."))
	output, err := cmd.Output()
	if err != nil {
		t.Logf("command failed: %v, output: %s", err, string(output))
	}

	// Parse findings
	var findings []map[string]interface{}
	if err := json.Unmarshal(output, &findings); err != nil {
		t.Fatalf("failed to parse JSON: %v\nOutput: %s", err, string(output))
	}

	// Should find secrets from both Helm and K8s
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings (one from Helm, one from K8s), got %d", len(findings))
	}

	foundHelm := false
	foundK8s := false
	for _, f := range findings {
		path, _ := f["path"].(string)
		if strings.Contains(path, "helm-charts") || strings.Contains(path, "my-app") {
			foundHelm = true
		}
		if strings.Contains(path, "k8s") && strings.Contains(path, "secret.yaml") {
			foundK8s = true
		}
	}

	if !foundHelm {
		t.Error("expected to find Helm chart findings")
	}
	if !foundK8s {
		t.Error("expected to find K8s manifest findings")
	}
}
