package artifacts

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// BenchmarkZipScanning benchmarks ZIP archive scanning with various sizes.
func BenchmarkZipScanning(b *testing.B) {
	sizes := []struct {
		name      string
		fileCount int
		fileSize  int
	}{
		{"small_10files_1KB", 10, 1024},
		{"medium_100files_10KB", 100, 10 * 1024},
		{"large_1000files_1KB", 1000, 1024},
	}

	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			zipData := createBenchZip(b, size.fileCount, size.fileSize)
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				r := bytes.NewReader(zipData)
				zr, err := zip.NewReader(r, int64(len(zipData)))
				if err != nil {
					b.Fatal(err)
				}

				for _, f := range zr.File {
					rc, err := f.Open()
					if err != nil {
						b.Fatal(err)
					}
					_, _ = io.Copy(io.Discard, rc)
					rc.Close()
				}
			}

			// Report throughput
			bytesPerOp := int64(len(zipData))
			b.SetBytes(bytesPerOp)
		})
	}
}

// BenchmarkTarGzScanning benchmarks tar.gz archive scanning.
func BenchmarkTarGzScanning(b *testing.B) {
	sizes := []struct {
		name      string
		fileCount int
		fileSize  int
	}{
		{"small_10files_1KB", 10, 1024},
		{"medium_100files_10KB", 100, 10 * 1024},
		{"large_1000files_1KB", 1000, 1024},
	}

	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			tarGzData := createBenchTarGz(b, size.fileCount, size.fileSize)
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				r := bytes.NewReader(tarGzData)
				gzr, err := gzip.NewReader(r)
				if err != nil {
					b.Fatal(err)
				}
				defer gzr.Close()

				tr := tar.NewReader(gzr)
				for {
					_, err := tr.Next()
					if err == io.EOF {
						break
					}
					if err != nil {
						b.Fatal(err)
					}
					_, _ = io.Copy(io.Discard, tr)
				}
			}

			b.SetBytes(int64(len(tarGzData)))
		})
	}
}

// BenchmarkHelmChartYAMLParsing benchmarks Helm Chart.yaml parsing.
func BenchmarkHelmChartYAMLParsing(b *testing.B) {
	tmpDir := b.TempDir()
	chartPath := filepath.Join(tmpDir, "Chart.yaml")

	chartYAML := `apiVersion: v2
name: benchmark-chart
version: 1.0.0
appVersion: "1.0"
description: A benchmark Helm chart for Kubernetes
type: application
keywords:
  - web
  - api
  - backend
maintainers:
  - name: Test Maintainer
    email: test@example.com
`
	if err := os.WriteFile(chartPath, []byte(chartYAML), 0644); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := ParseChartYAML(chartPath)
		if err != nil {
			b.Fatal(err)
		}
	}

	b.SetBytes(int64(len(chartYAML)))
}

// BenchmarkHelmValuesYAMLParsing benchmarks Helm values.yaml parsing.
func BenchmarkHelmValuesYAMLParsing(b *testing.B) {
	tmpDir := b.TempDir()
	valuesPath := filepath.Join(tmpDir, "values.yaml")

	valuesYAML := `replicaCount: 3
image:
  repository: nginx
  tag: "1.19"
  pullPolicy: IfNotPresent
service:
  type: ClusterIP
  port: 80
  targetPort: 8080
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: chart-example.local
      paths:
        - path: /
          pathType: ImplementationSpecific
resources:
  limits:
    cpu: 100m
    memory: 128Mi
  requests:
    cpu: 100m
    memory: 128Mi
`
	if err := os.WriteFile(valuesPath, []byte(valuesYAML), 0644); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := ParseValuesYAML(valuesPath)
		if err != nil {
			b.Fatal(err)
		}
	}

	b.SetBytes(int64(len(valuesYAML)))
}

// BenchmarkOCIManifestParsing benchmarks OCI manifest parsing.
func BenchmarkOCIManifestParsing(b *testing.B) {
	tmpDir := b.TempDir()
	manifestPath := filepath.Join(tmpDir, "manifest.json")

	manifestJSON := `{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7",
    "size": 7023
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:e692418e4000be24c5d0c4e2d64b1a0a84cf0b32cd8d1fdf5e69e8a2b2e0c1c5",
      "size": 32654
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:2a3b5e7f8c9d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f",
      "size": 16724
    }
  ]
}`

	if err := os.WriteFile(manifestPath, []byte(manifestJSON), 0644); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := ParseOCIManifest(manifestPath)
		if err != nil {
			b.Fatal(err)
		}
	}

	b.SetBytes(int64(len(manifestJSON)))
}

// BenchmarkNestedArchives benchmarks nested archive scanning (archive within archive).
func BenchmarkNestedArchives(b *testing.B) {
	tmpDir := b.TempDir()

	// Create inner zip
	innerZipPath := filepath.Join(tmpDir, "inner.zip")
	innerFiles := make(map[string]string)
	for i := 0; i < 10; i++ {
		innerFiles[fmt.Sprintf("file%d.txt", i)] = strings.Repeat("data", 100)
	}
	createZipFromMap(b, innerZipPath, innerFiles)

	// Create outer zip containing inner zip
	outerZipPath := filepath.Join(tmpDir, "outer.zip")
	innerData, err := os.ReadFile(innerZipPath)
	if err != nil {
		b.Fatal(err)
	}
	outerFiles := map[string]string{
		"inner.zip":  string(innerData),
		"readme.txt": "outer file",
	}
	createZipFromMap(b, outerZipPath, outerFiles)

	outerData, err := os.ReadFile(outerZipPath)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Simulate nested scanning
		r := bytes.NewReader(outerData)
		zr, err := zip.NewReader(r, int64(len(outerData)))
		if err != nil {
			b.Fatal(err)
		}

		for _, f := range zr.File {
			rc, err := f.Open()
			if err != nil {
				b.Fatal(err)
			}

			if strings.HasSuffix(f.Name, ".zip") {
				// Read inner zip
				innerData, _ := io.ReadAll(rc)
				innerReader := bytes.NewReader(innerData)
				innerZr, _ := zip.NewReader(innerReader, int64(len(innerData)))

				// Read inner files
				for _, innerFile := range innerZr.File {
					innerRc, _ := innerFile.Open()
					_, _ = io.Copy(io.Discard, innerRc)
					innerRc.Close()
				}
			} else {
				_, _ = io.Copy(io.Discard, rc)
			}
			rc.Close()
		}
	}

	b.SetBytes(int64(len(outerData)))
}

// Helper functions for benchmark data creation

func createBenchZip(b *testing.B, fileCount, fileSize int) []byte {
	b.Helper()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	content := strings.Repeat("x", fileSize)
	for i := 0; i < fileCount; i++ {
		w, err := zw.Create(fmt.Sprintf("file%d.txt", i))
		if err != nil {
			b.Fatal(err)
		}
		_, _ = w.Write([]byte(content))
	}

	if err := zw.Close(); err != nil {
		b.Fatal(err)
	}

	return buf.Bytes()
}

func createBenchTarGz(b *testing.B, fileCount, fileSize int) []byte {
	b.Helper()

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	content := strings.Repeat("x", fileSize)
	for i := 0; i < fileCount; i++ {
		hdr := &tar.Header{
			Name: fmt.Sprintf("file%d.txt", i),
			Mode: 0644,
			Size: int64(fileSize),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			b.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			b.Fatal(err)
		}
	}

	if err := tw.Close(); err != nil {
		b.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		b.Fatal(err)
	}

	return buf.Bytes()
}

//nolint:unused // Reserved for future Helm chart benchmarks
func createBenchHelmChart(b *testing.B, baseDir string, templateCount int) string {
	b.Helper()

	chartDir := filepath.Join(baseDir, "my-chart")
	if err := os.MkdirAll(chartDir, 0755); err != nil {
		b.Fatal(err)
	}

	// Create Chart.yaml
	chartYAML := `apiVersion: v2
name: benchmark-chart
version: 1.0.0
appVersion: "1.0"
description: A benchmark Helm chart
`
	if err := os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte(chartYAML), 0644); err != nil {
		b.Fatal(err)
	}

	// Create values.yaml
	valuesYAML := `replicaCount: 3
image:
  repository: nginx
  tag: "1.19"
service:
  type: ClusterIP
  port: 80
`
	if err := os.WriteFile(filepath.Join(chartDir, "values.yaml"), []byte(valuesYAML), 0644); err != nil {
		b.Fatal(err)
	}

	// Create templates directory
	templatesDir := filepath.Join(chartDir, "templates")
	if err := os.MkdirAll(templatesDir, 0755); err != nil {
		b.Fatal(err)
	}

	// Create template files
	for i := 0; i < templateCount; i++ {
		template := fmt.Sprintf(`apiVersion: v1
kind: ConfigMap
metadata:
  name: config-%d
data:
  key: value
  password: secret123
`, i)
		filename := filepath.Join(templatesDir, fmt.Sprintf("configmap-%d.yaml", i))
		if err := os.WriteFile(filename, []byte(template), 0644); err != nil {
			b.Fatal(err)
		}
	}

	return chartDir
}

//nolint:unused // Reserved for future Helm archive benchmarks
func createBenchHelmTgz(b *testing.B, outputPath string, templateCount int) {
	b.Helper()

	tmpDir := b.TempDir()
	chartDir := createBenchHelmChart(b, tmpDir, templateCount)

	// Package as tar.gz
	f, err := os.Create(outputPath)
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	// Walk chart directory and add to tar
	err = filepath.Walk(chartDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		relPath, _ := filepath.Rel(filepath.Dir(chartDir), path)

		hdr := &tar.Header{
			Name: relPath,
			Mode: 0644,
			Size: info.Size(),
		}

		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		_, err = tw.Write(data)
		return err
	})

	if err != nil {
		b.Fatal(err)
	}
}

func createZipFromMap(b *testing.B, path string, files map[string]string) {
	b.Helper()

	f, err := os.Create(path)
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			b.Fatal(err)
		}
		_, _ = w.Write([]byte(content))
	}

	if err := zw.Close(); err != nil {
		b.Fatal(err)
	}
}
