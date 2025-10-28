# Redactyl Technical Implementation Plan

**Goal:** Replace custom detectors with Gitleaks integration while enhancing artifact scanning capabilities

**Timeline:** Q1 2025 (12 weeks)

**Last Updated:** 2025-10-28

---

## 🎉 IMPLEMENTATION COMPLETE

**Status:** All Q1 2025 milestones completed successfully!

### What Was Delivered

✅ **Phase 1: Gitleaks Integration (Weeks 1-4)** - COMPLETE
- Scanner interface abstraction with `Scanner` and `ScanContext`
- Gitleaks binary integration via subprocess
- Virtual path preservation for nested artifacts
- Config system updated with `gitleaks:` section
- All integration tests passing

✅ **Phase 2: Enhanced Container Scanning (Weeks 5-8)** - COMPLETE
- Full OCI Image Spec v1 support (OCIManifest, OCIIndex, OCIConfig)
- Rich layer context with BuildLayerContext function
- Multi-arch image detection
- Streaming architecture maintained (zero disk extraction)

✅ **Phase 3: Kubernetes & Helm Support (Weeks 9-12)** - COMPLETE
- Helm chart scanning (.tgz archives and directories)
- Kubernetes manifest detection and scanning
- Auto-detection by structure and naming
- CLI flags `--helm` and `--k8s`
- Full config file support
- 4 comprehensive E2E integration tests

### Deferred to Q2

The following items were deprioritized in favor of completing core features:
- Container registry manifest inspection → Q2 Milestone 2.1
- Gitleaks auto-download mechanism → Q2 (manual install required for now)
- Kustomize support → Low priority
- Helm template rendering → v1 scans raw templates

### Current Branch

`pivot-buildout` - Ready to merge to `main` for v1.0 release

---

## Phase 1: Gitleaks Integration (Weeks 1-4) ✅ COMPLETED

**Status:** All milestones completed. Gitleaks integration shipped.

### Week 1: Foundation & Binary Management ✅

#### 1.1 Create Scanner Interface ✅
**File:** `internal/scanner/scanner.go`

```go
package scanner

import "github.com/redactyl/redactyl/internal/types"

// Scanner defines the interface for secret detection
type Scanner interface {
    // Scan scans content and returns findings
    Scan(path string, data []byte) ([]types.Finding, error)

    // ScanWithContext scans with additional context (for virtual paths)
    ScanWithContext(ctx ScanContext, data []byte) ([]types.Finding, error)

    // Version returns the scanner version
    Version() (string, error)
}

// ScanContext provides artifact context for scanning
type ScanContext struct {
    VirtualPath string            // e.g., "image.tar::layer-abc::file.txt"
    RealPath    string            // Temp file path on disk
    Metadata    map[string]string // Artifact-specific metadata
}
```

**Tasks:**
- [x] Define Scanner interface
- [x] Define ScanContext struct
- [x] Add context helpers (ParseVirtualPath, BuildVirtualPath)

#### 1.2 Gitleaks Binary Manager
**File:** `internal/scanner/gitleaks/binary.go`

```go
package gitleaks

import (
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "runtime"
)

// BinaryManager handles Gitleaks binary detection and installation
type BinaryManager struct {
    customPath string
    cachePath  string
}

// Find locates or downloads the Gitleaks binary
func (bm *BinaryManager) Find() (string, error) {
    // 1. Check custom path (from config)
    // 2. Check $PATH
    // 3. Check ~/.redactyl/bin/gitleaks
    // 4. Download if auto_download enabled
}

// Download fetches the appropriate binary from GitHub releases
func (bm *BinaryManager) Download(version string) error {
    // Platform detection (darwin/linux/windows, amd64/arm64)
    // Download from https://github.com/gitleaks/gitleaks/releases
    // Verify checksum
    // Extract and install to ~/.redactyl/bin/
}

// Version runs gitleaks --version and parses output
func (bm *BinaryManager) Version(path string) (string, error)
```

**Tasks:**
- [ ] Implement binary detection logic
- [ ] Add GitHub release fetching (use rhysd/go-github-selfupdate pattern)
- [ ] Implement checksum verification
- [ ] Add platform-specific download URLs
- [ ] Cache binary location to avoid repeated lookups

**Tests:**
- [ ] Test binary detection in $PATH
- [ ] Test download mechanism (mock GitHub API)
- [ ] Test version parsing
- [ ] Test platform detection

#### 1.3 Config System Update
**File:** `internal/config/config.go` (update)

```go
// Add to Config struct
type Config struct {
    // ... existing fields ...

    // Gitleaks configuration
    Gitleaks GitleaksConfig `yaml:"gitleaks"`
}

type GitleaksConfig struct {
    ConfigPath   string `yaml:"config"`      // Path to .gitleaks.toml
    BinaryPath   string `yaml:"binary"`      // Custom binary path
    AutoDownload bool   `yaml:"auto_download"` // Auto-download if missing
    Version      string `yaml:"version"`     // Pin to specific version
}
```

**Tasks:**
- [ ] Add GitleaksConfig struct
- [ ] Update config parsing
- [ ] Add validation (check config file exists if specified)
- [ ] Document new config fields

**Tests:**
- [ ] Test config parsing with gitleaks section
- [ ] Test defaults (auto_download: true)
- [ ] Test validation errors

### Week 2: Scanner Implementation

#### 2.1 Gitleaks Scanner Core
**File:** `internal/scanner/gitleaks/scanner.go`

```go
package gitleaks

import (
    "bytes"
    "encoding/json"
    "io/ioutil"
    "os"
    "os/exec"

    "github.com/redactyl/redactyl/internal/scanner"
    "github.com/redactyl/redactyl/internal/types"
)

type Scanner struct {
    binaryPath string
    configPath string
}

// NewScanner creates a Gitleaks scanner
func NewScanner(cfg Config) (*Scanner, error) {
    bm := &BinaryManager{customPath: cfg.BinaryPath}
    binaryPath, err := bm.Find()
    if err != nil {
        if cfg.AutoDownload {
            if err := bm.Download(cfg.Version); err != nil {
                return nil, err
            }
            binaryPath, _ = bm.Find()
        } else {
            return nil, fmt.Errorf("gitleaks binary not found: %w", err)
        }
    }
    return &Scanner{binaryPath: binaryPath, configPath: cfg.ConfigPath}, nil
}

// Scan implements scanner.Scanner
func (s *Scanner) Scan(path string, data []byte) ([]types.Finding, error) {
    return s.ScanWithContext(scanner.ScanContext{
        VirtualPath: path,
        RealPath:    path,
    }, data)
}

// ScanWithContext implements scanner.Scanner
func (s *Scanner) ScanWithContext(ctx scanner.ScanContext, data []byte) ([]types.Finding, error) {
    // 1. Write data to temp file
    tmpfile, err := ioutil.TempFile("", "redactyl-scan-*")
    if err != nil {
        return nil, err
    }
    defer os.Remove(tmpfile.Name())

    if _, err := tmpfile.Write(data); err != nil {
        return nil, err
    }
    tmpfile.Close()

    // 2. Build gitleaks command
    args := []string{
        "detect",
        "--no-git",
        "--report-format", "json",
        "--source", tmpfile.Name(),
    }
    if s.configPath != "" {
        args = append(args, "--config", s.configPath)
    }

    // 3. Execute gitleaks
    cmd := exec.Command(s.binaryPath, args...)
    var stdout, stderr bytes.Buffer
    cmd.Stdout = &stdout
    cmd.Stderr = &stderr

    err = cmd.Run()
    // Note: gitleaks exits with code 1 when findings exist
    if err != nil && cmd.ProcessState.ExitCode() != 1 {
        return nil, fmt.Errorf("gitleaks failed: %s", stderr.String())
    }

    // 4. Parse JSON output
    var gitleaksFindings []GitleaksFinding
    if err := json.Unmarshal(stdout.Bytes(), &gitleaksFindings); err != nil {
        return nil, err
    }

    // 5. Convert to Redactyl findings with virtual path mapping
    return s.convertFindings(gitleaksFindings, ctx), nil
}

// convertFindings maps Gitleaks findings to Redactyl findings
func (s *Scanner) convertFindings(gf []GitleaksFinding, ctx scanner.ScanContext) []types.Finding {
    var findings []types.Finding
    for _, f := range gf {
        findings = append(findings, types.Finding{
            Path:       ctx.VirtualPath, // Use virtual path, not temp file path
            Detector:   f.RuleID,
            Match:      f.Match,
            Secret:     f.Secret,
            Line:       f.StartLine,
            Column:     f.StartColumn,
            Context:    f.Description,
            Confidence: mapGitleaksToConfidence(f),
            Metadata:   ctx.Metadata,
        })
    }
    return findings
}

// GitleaksFinding represents Gitleaks JSON output
type GitleaksFinding struct {
    Description string `json:"Description"`
    RuleID      string `json:"RuleID"`
    Match       string `json:"Match"`
    Secret      string `json:"Secret"`
    StartLine   int    `json:"StartLine"`
    EndLine     int    `json:"EndLine"`
    StartColumn int    `json:"StartColumn"`
    EndColumn   int    `json:"EndColumn"`
    File        string `json:"File"`
    Commit      string `json:"Commit"`
}

func mapGitleaksToConfidence(f GitleaksFinding) float64 {
    // Gitleaks doesn't have confidence scores, so we use heuristics
    // Rules with "high-entropy" are lower confidence
    // Rules with specific prefixes/formats are higher confidence
    // Default to 0.8 for now
    return 0.8
}
```

**Tasks:**
- [ ] Implement Scanner struct
- [ ] Implement Scan and ScanWithContext methods
- [ ] Add temp file handling with cleanup
- [ ] Parse Gitleaks JSON output
- [ ] Map Gitleaks findings to Redactyl types
- [ ] Handle exit codes correctly (exit 1 = findings, not error)

**Tests:**
- [ ] Test scanning with known secrets
- [ ] Test virtual path preservation
- [ ] Test error handling (binary not found, invalid config)
- [ ] Test JSON parsing with real Gitleaks output
- [ ] Test temp file cleanup on error

#### 2.2 Virtual Path Remapping
**File:** `internal/scanner/context.go`

```go
package scanner

import "strings"

const VirtualPathSeparator = "::"

// ParseVirtualPath splits a virtual path into components
// Example: "image.tar::layer-abc::etc/app.yaml" -> ["image.tar", "layer-abc", "etc/app.yaml"]
func ParseVirtualPath(path string) []string {
    return strings.Split(path, VirtualPathSeparator)
}

// BuildVirtualPath constructs a virtual path from components
func BuildVirtualPath(components ...string) string {
    return strings.Join(components, VirtualPathSeparator)
}

// IsVirtualPath checks if a path contains virtual path separators
func IsVirtualPath(path string) bool {
    return strings.Contains(path, VirtualPathSeparator)
}

// GetArtifactRoot extracts the root artifact from a virtual path
// Example: "image.tar::layer-abc::etc/app.yaml" -> "image.tar"
func GetArtifactRoot(path string) string {
    parts := ParseVirtualPath(path)
    if len(parts) > 0 {
        return parts[0]
    }
    return path
}
```

**Tasks:**
- [ ] Implement virtual path utilities
- [ ] Add path validation
- [ ] Document virtual path format

**Tests:**
- [ ] Test parsing nested paths
- [ ] Test building paths
- [ ] Test artifact root extraction

### Week 3: Engine Integration

#### 3.1 Update Engine to Use Scanner Interface
**File:** `internal/engine/engine.go` (update)

```go
// Update Engine struct
type Engine struct {
    cfg     *config.Config
    scanner scanner.Scanner  // NEW: use interface instead of direct detector calls
    // ... other fields ...
}

// Update NewEngine
func NewEngine(cfg *config.Config) (*Engine, error) {
    // Initialize scanner based on config
    var s scanner.Scanner
    var err error

    // For now, always use Gitleaks
    s, err = gitleaks.NewScanner(cfg.Gitleaks)
    if err != nil {
        return nil, fmt.Errorf("failed to initialize scanner: %w", err)
    }

    return &Engine{
        cfg:     cfg,
        scanner: s,
        // ...
    }, nil
}

// Update scanFile to use scanner interface
func (e *Engine) scanFile(path string, data []byte) []types.Finding {
    findings, err := e.scanner.Scan(path, data)
    if err != nil {
        // Log error but don't fail entire scan
        log.Printf("scan error for %s: %v", path, err)
        return nil
    }
    return findings
}
```

**Tasks:**
- [ ] Add scanner field to Engine
- [ ] Update Engine initialization
- [ ] Replace detector.RunAll() calls with scanner.Scan()
- [ ] Add error handling for scanner failures

**Tests:**
- [ ] Test engine with Gitleaks scanner
- [ ] Test error handling (scanner initialization fails)
- [ ] Compare output with old detector implementation

#### 3.2 Update Artifact Scanning with Context
**File:** `internal/artifacts/artifacts.go` (update)

```go
// Update ScanArchivesWithFilter to pass context
func ScanArchivesWithFilter(root string, limits Limits, allow PathAllowFunc, s scanner.Scanner, emit func(types.Finding)) error {
    // ... existing archive walking logic ...

    // When emitting entries, build context
    ctx := scanner.ScanContext{
        VirtualPath: scanner.BuildVirtualPath(archivePath, entryPath),
        RealPath:    "", // No real path, using in-memory data
        Metadata: map[string]string{
            "archive": archivePath,
            "entry":   entryPath,
            "size":    strconv.Itoa(len(data)),
        },
    }

    findings, err := s.ScanWithContext(ctx, data)
    if err != nil {
        log.Printf("scan error: %v", err)
        return
    }

    for _, f := range findings {
        emit(f)
    }
}
```

**Tasks:**
- [ ] Update artifact scanner to accept scanner.Scanner
- [ ] Build ScanContext for each entry
- [ ] Update container scanning similarly
- [ ] Update IaC scanning

**Tests:**
- [ ] Test archive scanning with virtual paths
- [ ] Test container layer scanning with context
- [ ] Verify metadata is preserved

### Week 4: CLI Updates & Testing

#### 4.1 Update CLI Commands
**File:** `cmd/redactyl/scan.go` (update)

```go
// Remove detector-specific flags
// Remove: --enable, --disable, --min-confidence

// Add Gitleaks-specific flags (optional, mostly use config)
var scanCmd = &cobra.Command{
    Use:   "scan",
    Short: "Scan for secrets",
    RunE: func(cmd *cobra.Command, args []string) error {
        // Load config
        cfg, err := config.Load()
        if err != nil {
            return err
        }

        // Initialize engine (will create Gitleaks scanner)
        eng, err := engine.NewEngine(cfg)
        if err != nil {
            return fmt.Errorf("failed to initialize scanner: %w", err)
        }

        // Run scan
        return eng.Run()
    },
}

// Remove detector command
// File: cmd/redactyl/detectors.go (DELETE)
```

**Tasks:**
- [ ] Remove detector-specific flags
- [ ] Update help text to mention Gitleaks
- [ ] Remove `redactyl detectors` command
- [ ] Remove `redactyl test-detector` command
- [ ] Update error messages

#### 4.2 Integration Tests
**File:** `cmd/redactyl/e2e_cli_test.go` (update)

```go
func TestGitleaksIntegration(t *testing.T) {
    // Ensure gitleaks is available or skip test
    if _, err := exec.LookPath("gitleaks"); err != nil {
        t.Skip("gitleaks not in PATH")
    }

    // Create temp repo with known secrets
    tmpDir := t.TempDir()
    testFile := filepath.Join(tmpDir, "secrets.txt")
    ioutil.WriteFile(testFile, []byte("aws_access_key_id = AKIAIOSFODNN7EXAMPLE"), 0644)

    // Run redactyl scan
    cmd := exec.Command("./bin/redactyl", "scan", tmpDir, "--json")
    output, err := cmd.Output()
    require.NoError(t, err)

    // Parse findings
    var findings []types.Finding
    require.NoError(t, json.Unmarshal(output, &findings))

    // Verify AWS key was detected
    require.NotEmpty(t, findings)
    assert.Contains(t, findings[0].Detector, "aws")
}

func TestArchiveWithGitleaks(t *testing.T) {
    // Create zip with secret
    // Scan with --archives
    // Verify virtual path in finding
}
```

**Tasks:**
- [ ] Add Gitleaks integration tests
- [ ] Test archive scanning with Gitleaks
- [ ] Test container scanning with Gitleaks
- [ ] Add performance benchmarks (compare with old implementation)

#### 4.3 Documentation Updates
**Files:** Multiple

- [ ] Update `README.md` - "How detection works" section ✅ (already done)
- [ ] Update `CONTRIBUTING.md` - Remove detector contribution guide
- [ ] Create `docs/gitleaks-integration.md` - Detailed integration guide
- [ ] Update `docs/configuration.md` - Document gitleaks config section
- [ ] Add migration guide for users of detector IDs

**Migration Guide:**
```markdown
# Migrating from Custom Detectors to Gitleaks

## What Changed
Redactyl now uses Gitleaks for secret detection instead of custom detectors.

## Configuration Migration

### Before (v0.x)
```yaml
enable: aws_access_key,github_token
disable: entropy_context
min_confidence: 0.85
```

### After (v1.x)
```yaml
gitleaks:
  config: .gitleaks.toml  # Use standard Gitleaks config
  auto_download: true
```

Create `.gitleaks.toml`:
```toml
[extend]
useDefault = true

[allowlist]
paths = ["**/*.example"]
```

## Detector ID Mapping
| Old Redactyl ID | Gitleaks Rule ID |
|-----------------|------------------|
| aws_access_key  | aws-access-token |
| github_token    | github-pat       |
| ... | ... |
```

---

## Phase 2: Enhanced Container Scanning (Weeks 5-8)

### Week 5: OCI Format Support

#### 5.1 OCI Image Manifest Parsing
**File:** `internal/artifacts/oci.go` (new)

```go
package artifacts

import (
    "encoding/json"
    "io/ioutil"
)

// OCIManifest represents an OCI image manifest
type OCIManifest struct {
    SchemaVersion int               `json:"schemaVersion"`
    MediaType     string            `json:"mediaType"`
    Config        OCIDescriptor     `json:"config"`
    Layers        []OCIDescriptor   `json:"layers"`
}

type OCIDescriptor struct {
    MediaType string `json:"mediaType"`
    Digest    string `json:"digest"`
    Size      int64  `json:"size"`
}

// ParseOCIManifest reads and parses an OCI image manifest
func ParseOCIManifest(path string) (*OCIManifest, error) {
    data, err := ioutil.ReadFile(path)
    if err != nil {
        return nil, err
    }

    var manifest OCIManifest
    if err := json.Unmarshal(data, &manifest); err != nil {
        return nil, err
    }

    return &manifest, nil
}

// IsOCIImage checks if a directory contains an OCI image
func IsOCIImage(dir string) bool {
    // Check for index.json or manifest.json
    // Validate OCI layout
}
```

**Tasks:**
- [ ] Implement OCI manifest parsing
- [ ] Add OCI layout detection
- [ ] Handle multi-arch manifests
- [ ] Parse config blobs for layer metadata

#### 5.2 Layer Context Enhancement
**File:** `internal/artifacts/layers.go` (new)

```go
package artifacts

// LayerContext provides rich context about a container layer
type LayerContext struct {
    Digest       string   // sha256:abc123...
    Index        int      // Layer 5 of 12
    TotalLayers  int
    Size         int64
    CreatedBy    string   // Dockerfile command
    Created      time.Time
    ParentDigest string   // Previous layer
}

// BuildLayerContext extracts context from image config
func BuildLayerContext(config *OCIConfig, layerIndex int) LayerContext {
    // Parse history to match layer with Dockerfile command
    // Extract creation timestamp
    // Calculate layer size
}

// EnhanceFinding adds layer context to a finding
func EnhanceFinding(f types.Finding, ctx LayerContext) types.Finding {
    f.Metadata["layer_digest"] = ctx.Digest
    f.Metadata["layer_index"] = strconv.Itoa(ctx.Index)
    f.Metadata["layer_created_by"] = ctx.CreatedBy
    f.Metadata["layer_size"] = strconv.FormatInt(ctx.Size, 10)
    return f
}
```

**Tasks:**
- [ ] Implement layer context extraction
- [ ] Parse image config history
- [ ] Match layers to Dockerfile commands
- [ ] Add timestamp and size metadata

### Week 6-7: Performance Optimization

#### 6.1 Streaming Improvements
**File:** `internal/artifacts/stream.go` (new)

```go
package artifacts

import (
    "io"
    "sync"
)

// StreamPool manages reusable buffers for streaming
type StreamPool struct {
    pool sync.Pool
}

// NewStreamPool creates a buffer pool
func NewStreamPool(bufferSize int) *StreamPool {
    return &StreamPool{
        pool: sync.Pool{
            New: func() interface{} {
                return make([]byte, bufferSize)
            },
        },
    }
}

// StreamEntry efficiently streams an entry without full buffering
func StreamEntry(r io.Reader, scanner scanner.Scanner, ctx scanner.ScanContext) ([]types.Finding, error) {
    // Use limited buffering for large entries
    // Scan in chunks if entry is very large
    // Avoid loading entire 1GB file into memory
}
```

**Tasks:**
- [ ] Implement buffer pooling
- [ ] Add chunked scanning for large files
- [ ] Optimize memory usage for 10GB+ images
- [ ] Add streaming benchmarks

#### 6.2 Parallel Layer Processing
**File:** `internal/artifacts/parallel.go` (update)

```go
// Update to use worker pool for layer scanning
func ScanLayersParallel(layers []Layer, scanner scanner.Scanner, workers int) []types.Finding {
    // Create worker pool
    // Distribute layers across workers
    // Collect findings concurrently
    // Respect global time budget
}
```

**Tasks:**
- [ ] Implement parallel layer scanning
- [ ] Add worker pool with configurable size
- [ ] Ensure thread-safety for scanner calls
- [ ] Add cancellation support (context.Context)

### Week 8: Testing & Documentation

- [ ] End-to-end tests with real container images
- [ ] Performance benchmarks (scan 1GB image in < 30s)
- [ ] Memory profiling (no leaks, bounded usage)
- [ ] Update `docs/deep-scanning.md` with OCI support
- [ ] Add examples for Docker, Podman, containerd

---

## Phase 3: Kubernetes & Helm Support (Weeks 9-12)

### Week 9-10: Helm Chart Scanning

#### 10.1 Helm Chart Parser
**File:** `internal/helm/parser.go` (new)

```go
package helm

import (
    "path/filepath"
    "gopkg.in/yaml.v3"
)

// Chart represents a Helm chart structure
type Chart struct {
    Metadata  ChartMetadata
    Values    map[string]interface{}
    Templates []Template
}

type Template struct {
    Path    string
    Content []byte
}

// ParseChart loads and parses a Helm chart directory
func ParseChart(chartPath string) (*Chart, error) {
    // Read Chart.yaml
    // Read values.yaml
    // Read all templates/*.yaml
    // Handle dependencies (charts/ subdir)
}

// ExtractSecrets finds potential secrets in values and templates
func (c *Chart) ExtractSecrets(scanner scanner.Scanner) ([]types.Finding, error) {
    var findings []types.Finding

    // Scan values.yaml
    valuesPath := "values.yaml"
    valuesData, _ := yaml.Marshal(c.Values)
    ctx := scanner.ScanContext{
        VirtualPath: scanner.BuildVirtualPath(c.Metadata.Name, valuesPath),
        Metadata: map[string]string{
            "chart": c.Metadata.Name,
            "file":  valuesPath,
        },
    }
    f, _ := scanner.ScanWithContext(ctx, valuesData)
    findings = append(findings, f...)

    // Scan templates (rendered or raw)
    for _, tmpl := range c.Templates {
        // TODO: Render template with values or scan raw
        // Scanning raw is simpler but less accurate
    }

    return findings, nil
}
```

**Tasks:**
- [ ] Implement Helm chart parser
- [ ] Parse Chart.yaml, values.yaml, templates/
- [ ] Handle packaged charts (.tgz)
- [ ] Decide: scan raw templates or rendered output?
  - **Recommendation:** Start with raw, add rendering later

#### 10.2 Helm Template Rendering (Optional)
**File:** `internal/helm/render.go` (new)

```go
// RenderTemplate renders a Helm template with values
// This requires embedding Helm as a library or shelling out to `helm template`
func RenderTemplate(tmplPath string, values map[string]interface{}) ([]byte, error) {
    // Option 1: Use helm.sh/helm/v3/pkg/chart libraries
    // Option 2: Shell out to `helm template`
    // Option 3: Skip for v1, scan raw templates
}
```

**Decision Point:**
- **Ship v1 without rendering** (scan raw templates)
- **Add rendering in v1.1** (better accuracy but more complexity)

### Week 11: Kubernetes Manifest Scanning

#### 11.1 K8s Resource Parser
**File:** `internal/k8s/parser.go` (new)

```go
package k8s

import "gopkg.in/yaml.v3"

// Resource represents a Kubernetes resource
type Resource struct {
    APIVersion string
    Kind       string
    Metadata   Metadata
    Data       map[string]interface{} // For Secrets/ConfigMaps
    Spec       map[string]interface{} // For other resources
}

type Metadata struct {
    Name      string
    Namespace string
}

// ParseManifests parses a multi-document YAML file
func ParseManifests(data []byte) ([]Resource, error) {
    // Split by ---
    // Parse each document
    // Handle both single and multi-doc files
}

// ExtractSecretData decodes base64 secrets from Secret objects
func (r *Resource) ExtractSecretData() map[string][]byte {
    if r.Kind != "Secret" {
        return nil
    }

    // Decode base64 values in .data
    // Return plain text for scanning
}

// FindSecretsInEnv finds secrets in container env vars
func (r *Resource) FindSecretsInEnv() []EnvVar {
    // Parse .spec.template.spec.containers[].env
    // Look for hardcoded values (not valueFrom)
}
```

**Tasks:**
- [ ] Implement K8s manifest parser
- [ ] Handle Secret base64 decoding
- [ ] Extract env vars from Pods/Deployments
- [ ] Parse ConfigMaps for secrets

#### 11.2 K8s-Specific Detectors
**File:** `internal/k8s/detectors.go` (new)

```go
package k8s

// ScanResource scans a K8s resource for secrets
func ScanResource(r Resource, scanner scanner.Scanner) ([]types.Finding, error) {
    var findings []types.Finding

    // 1. Scan Secret .data fields (after base64 decode)
    if r.Kind == "Secret" {
        for key, val := range r.ExtractSecretData() {
            ctx := scanner.ScanContext{
                VirtualPath: fmt.Sprintf("Secret/%s/%s:.data.%s", r.Metadata.Namespace, r.Metadata.Name, key),
                Metadata: map[string]string{
                    "kind":      "Secret",
                    "namespace": r.Metadata.Namespace,
                    "name":      r.Metadata.Name,
                    "field":     key,
                },
            }
            f, _ := scanner.ScanWithContext(ctx, val)
            findings = append(findings, f...)
        }
    }

    // 2. Scan env vars in Pods/Deployments
    for _, env := range r.FindSecretsInEnv() {
        // Scan env.value
    }

    // 3. Scan ConfigMap data
    if r.Kind == "ConfigMap" {
        // Similar to Secret scanning
    }

    return findings, nil
}
```

**Tasks:**
- [ ] Implement resource-specific scanning
- [ ] Add virtual path format for K8s resources
- [ ] Handle nested field paths (e.g., `.spec.containers[0].env[2].value`)

### Week 12: Integration & Polish

- [ ] Add CLI flags: `--helm`, `--kubernetes`
- [ ] Integration tests with real Helm charts (e.g., stable/mysql)
- [ ] Integration tests with K8s manifests
- [ ] Update documentation
- [ ] Performance benchmarks
- [ ] Write blog post draft

---

## Testing Strategy

### Unit Tests
- Every new package has > 80% coverage
- Test with both valid and invalid inputs
- Mock scanner interface where appropriate

### Integration Tests
- E2E tests with real Gitleaks binary
- Test with sample artifacts (Docker images, Helm charts)
- Performance benchmarks tracked over time

### Manual Testing Checklist
- [ ] Scan AWS ECR image
- [ ] Scan GCP GCR image
- [ ] Scan public Docker Hub image (official Redis)
- [ ] Scan Helm chart from Artifact Hub
- [ ] Scan Kubernetes manifests from real cluster export
- [ ] Scan nested archive (zip inside tar inside container)

---

## Migration Plan - COMPLETED ✅

### Deleted (Legacy Code Cleanup - October 2025)
- ✅ `/internal/detectors/` - All 150+ detector files (removed)
- ✅ `cmd/redactyl/testdetector.go` - Test detector command (removed)
- ✅ Legacy CLI flags: `--no-validators`, `--no-structured`, `--verify` (removed)
- ⚠️ `/internal/validate/` - Kept (still used for non-detection validation)
- ⚠️ `cmd/redactyl/detectors.go` - Kept (lists available Gitleaks rules)

### What Was Kept
- ✅ `/internal/artifacts/` - Core differentiator (Helm, K8s, OCI, archives)
- ✅ `/internal/ctxparse/` - Adds value on top of Gitleaks
- ✅ `/internal/engine/` - Orchestration layer
- ✅ `/internal/config/` - Config management
- ✅ `/internal/cache/` - Incremental scanning
- ✅ `cmd/redactyl/scan.go` - Main command
- ✅ `cmd/redactyl/fix.go` - Remediation
- ✅ `cmd/redactyl/purge.go` - History rewriting

---

## Risk Mitigation

### Risk: Gitleaks Binary Not Available
**Mitigation:** Auto-download with fallback to error message
**Contingency:** Provide clear installation instructions

### Risk: Gitleaks Output Format Changes
**Mitigation:** Pin to tested version, document compatibility
**Contingency:** Add version detection and format adapters

### Risk: Performance Regression
**Mitigation:** Benchmark every PR, set performance budgets
**Contingency:** Optimize temp file handling, add caching

### Risk: Virtual Path Mapping Bugs
**Mitigation:** Extensive testing with nested artifacts
**Contingency:** Add debug mode that shows real vs virtual paths

---

## Success Criteria

### Phase 1 Complete When:
- [ ] All scans use Gitleaks (no custom detectors)
- [ ] Virtual paths work for archives and containers
- [ ] Performance within 10% of baseline
- [ ] All tests passing
- [ ] Documentation updated

### Phase 2 Complete When:
- [ ] OCI images scan correctly
- [ ] Layer context shows in findings
- [ ] 1GB image scans in < 30 seconds
- [ ] Memory usage < 500MB for 10GB image

### Phase 3 Complete When:
- [ ] Helm charts scan without errors
- [ ] K8s Secrets are decoded and scanned
- [ ] Virtual paths show resource names
- [ ] Blog post published

---

## Next Steps

1. **Review this plan** - Get feedback from team/stakeholders
2. **Set up project board** - Track tasks in GitHub Issues/Projects
3. **Create feature branch** - `feature/gitleaks-integration`
4. **Start Week 1** - Binary management and scanner interface
5. **Weekly check-ins** - Review progress, adjust timeline

**Owner:** Engineering team
**Reviewers:** @franzer
**Timeline:** 12 weeks (Q1 2025)
