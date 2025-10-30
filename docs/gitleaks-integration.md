# Gitleaks Integration

Redactyl uses [Gitleaks](https://github.com/gitleaks/gitleaks) as its secret detection engine. This document explains how the integration works, how to configure it, and how to extend it.

## Architecture Overview

Redactyl focuses on **artifact intelligence** while Gitleaks handles **pattern matching**. This separation of concerns creates a powerful combination:

```
┌─────────────────────────────────────────┐
│         Redactyl Artifact Layer         │
│  ┌───────────────────────────────────┐  │
│  │ Parse complex artifacts:          │  │
│  │ - Container images (OCI format)   │  │
│  │ - Helm charts (.tgz + dirs)       │  │
│  │ - Kubernetes manifests            │  │
│  │ - Nested archives (zip, tar, tgz) │  │
│  │ - IaC files (tfstate, kubeconfig) │  │
│  └────────────┬──────────────────────┘  │
│               │ Extract & stream files  │
│               ▼                          │
│  ┌───────────────────────────────────┐  │
│  │ Virtual Path Tracking             │  │
│  │ chart.tgz::templates/secret.yaml  │  │
│  └────────────┬──────────────────────┘  │
└───────────────┼──────────────────────────┘
                │ Pass content to scanner
                ▼
┌─────────────────────────────────────────┐
│      Gitleaks Detection Engine          │
│  ┌───────────────────────────────────┐  │
│  │ Pattern matching with 200+ rules: │  │
│  │ - AWS keys, GCP keys, Azure keys  │  │
│  │ - GitHub tokens, GitLab tokens    │  │
│  │ - Private keys (RSA, ECDSA, etc.) │  │
│  │ - Database credentials            │  │
│  │ - API keys and secrets            │  │
│  └────────────┬──────────────────────┘  │
│               │ Return findings          │
│               ▼                          │
│  ┌───────────────────────────────────┐  │
│  │ JSON output with metadata         │  │
│  └────────────┬──────────────────────┘  │
└───────────────┼──────────────────────────┘
                │ Parse findings
                ▼
┌─────────────────────────────────────────┐
│       Redactyl Result Enrichment        │
│  ┌───────────────────────────────────┐  │
│  │ Enhance findings with:            │  │
│  │ - Virtual path context            │  │
│  │ - Artifact metadata               │  │
│  │ - Layer/archive information       │  │
│  │ - Structured field context        │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

## How It Works

### 1. Binary Management

Redactyl includes a `BinaryManager` (`internal/scanner/gitleaks/binary.go`) that handles Gitleaks binary discovery and installation:

**Search Order:**
1. Custom path (if specified via config)
2. `$PATH` lookup
3. Cached binary in `~/.redactyl/bin/gitleaks`

**Auto-Download:**
When enabled (default), Redactyl automatically downloads Gitleaks from GitHub releases if not found:
- Detects platform (darwin/linux/windows, amd64/arm64/etc.)
- Downloads appropriate archive from GitHub releases
- Extracts binary to `~/.redactyl/bin/`
- Makes executable (Unix only)

### 2. Scanner Abstraction

Redactyl uses a `Scanner` interface to decouple detection engines:

```go
type Scanner interface {
    Scan(path string, data []byte) ([]types.Finding, error)
    ScanWithContext(ctx ScanContext, data []byte) ([]types.Finding, error)
    Version() (string, error)
}
```

The `ScanContext` preserves artifact metadata through the scanning process:

```go
type ScanContext struct {
    VirtualPath string            // e.g., "chart.tgz::templates/secret.yaml"
    RealPath    string            // Temp file path on disk
    Metadata    map[string]string // Artifact-specific metadata
}
```

### 3. Scanning Process

**For each file extracted from an artifact:**

1. **Write to temp file**: Gitleaks requires files on disk
2. **Call Gitleaks**: `gitleaks detect --no-git --report-path=/tmp/report.json /tmp/file`
3. **Parse JSON output**: Read findings from report file
4. **Remap paths**: Convert temp paths back to virtual paths
5. **Enrich metadata**: Add artifact context and Gitleaks rule IDs

### 4. Finding Conversion

Gitleaks findings are converted to Redactyl's `types.Finding`:

```go
// Gitleaks JSON finding
{
  "Description": "AWS Access Key",
  "RuleID": "aws-access-token",
  "Match": "AKIA...",
  "Secret": "AKIA...",
  "File": "/tmp/file123",
  "Line": "password = AKIA...",
  "StartLine": 42,
  "EndLine": 42,
  "StartColumn": 12,
  "EndColumn": 32,
  "Entropy": 4.8
}

// Converted to Redactyl finding
{
  "path": "chart.tgz::templates/secret.yaml",
  "line": 42,
  "column": 12,
  "match": "AKIA...",
  "description": "AWS Access Key",
  "confidence": 0.90,  // Mapped from entropy
  "metadata": {
    "gitleaks_rule_id": "aws-access-token",
    "artifact_type": "helm",
    "chart_name": "mychart",
    "chart_version": "1.0.0"
  }
}
```

### 5. Confidence Mapping

Gitleaks provides entropy scores; Redactyl maps these to confidence levels for `--fail-on` thresholds:

| Entropy | Confidence | Description |
|---------|-----------|-------------|
| > 4.5   | 0.85-1.0  | High confidence (likely real secret) |
| 3.5-4.5 | 0.70-0.84 | Medium confidence |
| < 3.5   | 0.50-0.69 | Low confidence (possible false positive) |

## Configuration

### Basic Configuration

```yaml
# .redactyl.yml
gitleaks:
  # Path to custom Gitleaks config (optional)
  config: .gitleaks.toml

  # Explicit binary path (optional)
  binary: /usr/local/bin/gitleaks

  # Auto-download if not found (default: true)
  auto_download: true

  # Version to download (default: latest)
  version: 8.18.0
```

### Gitleaks Configuration

Redactyl respects standard Gitleaks `.gitleaks.toml` files. Create one to customize detection:

```toml
# .gitleaks.toml

# Use default rules as base
[extend]
useDefault = true

# Add custom rules
[[rules]]
id = "company-api-key"
description = "Company API Key"
regex = '''company_key_[a-zA-Z0-9]{32}'''
entropy = 3.5

[[rules]]
id = "internal-token"
description = "Internal Auth Token"
regex = '''internal_token:\s*[a-zA-Z0-9]{64}'''

# Allowlist patterns
[allowlist]
description = "Allowlist certain paths and patterns"
paths = [
  '''.*\.example$''',
  '''.*test.*''',
  '''.*mock.*'''
]
regexes = [
  '''placeholder_secret''',
  '''example_password''',
  '''test_key_[0-9]+'''
]
```

See [Gitleaks Configuration Docs](https://github.com/gitleaks/gitleaks#configuration) for full details.

### CLI Overrides

Filter Gitleaks findings via CLI:

```bash
# Only show specific rule IDs
redactyl scan --enable "aws-access-token,github-pat,private-key"

# Exclude specific rule IDs
redactyl scan --disable "generic-api-key"

# Combine filters
redactyl scan --enable "aws-*,gcp-*" --disable "generic-api-key"
```

Note: These flags filter results **after** scanning. To modify Gitleaks rules themselves, use a `.gitleaks.toml` file.

## Performance Considerations

### Temp File Overhead

Gitleaks requires files on disk, so Redactyl:
- Creates temp files for each extracted file
- Cleans up immediately after scanning
- Reuses temp directory per artifact to reduce syscalls

**Optimization:** For large artifacts (1000+ files), temp file creation is ~5-10% of total scan time.

### Parallel Scanning

Redactyl uses a worker pool (sized by `--threads` flag) to scan multiple files concurrently:
- Default: `runtime.NumCPU()` workers
- Each worker calls Gitleaks independently
- Findings are aggregated after scanning

**Optimization:** With 8 cores, scanning 1000 files takes ~10s vs ~60s sequential.

### Caching

Currently, Redactyl does not cache Gitleaks findings. Future versions may add:
- Content-addressed caching (hash-based)
- Layer-level caching for containers
- Cross-scan result reuse

## Troubleshooting

### Gitleaks Not Found

```
Error: gitleaks binary not found in PATH or cache
```

**Solutions:**
1. Install manually: `brew install gitleaks` (macOS) or download from [releases](https://github.com/gitleaks/gitleaks/releases)
2. Enable auto-download in config: `gitleaks.auto_download: true`
3. Specify explicit path: `gitleaks.binary: /path/to/gitleaks`

### Auto-Download Fails

```
Error: failed to download gitleaks: HTTP 404
```

**Causes:**
- Invalid version specified
- GitHub rate limiting
- Network connectivity issues

**Solutions:**
1. Check version exists: https://github.com/gitleaks/gitleaks/releases
2. Use `latest` instead of specific version
3. Install manually and specify path

### Version Mismatch

```
Warning: Gitleaks version 7.x detected, 8.x recommended
```

Redactyl works with Gitleaks 7.x and 8.x, but 8.x is recommended for:
- Better performance
- More detection rules
- Improved JSON output

Update: `redactyl config set gitleaks.version 8.18.0` or install manually.

### False Positives

If Gitleaks reports false positives:

1. **Use `.gitleaks.toml` allowlist:**
   ```toml
   [allowlist]
   paths = ['''testdata/.*''']
   regexes = ['''fake_secret_for_testing''']
   ```

2. **Filter via CLI:**
   ```bash
   redactyl scan --disable "generic-api-key"
   ```

3. **Adjust confidence threshold:**
   ```bash
   redactyl scan --min-confidence 0.80  # Only high-confidence findings
   ```

## Extending the Integration

### Adding Custom Rules

Contribute rules to Gitleaks (benefits everyone) or add locally:

1. Create `.gitleaks.toml` in repo root
2. Add custom rule:
   ```toml
   [[rules]]
   id = "my-custom-rule"
   description = "My Custom Secret Pattern"
   regex = '''my_pattern_here'''
   entropy = 4.0
   ```
3. Test: `redactyl scan --gitleaks-config .gitleaks.toml`

### Alternative Scanners

The `Scanner` interface allows plugging in alternative engines:

```go
// internal/scanner/custom/scanner.go
type CustomScanner struct {}

func (s *CustomScanner) ScanWithContext(ctx scanner.ScanContext, data []byte) ([]types.Finding, error) {
    // Your detection logic here
    return findings, nil
}
```

Register in engine:
```go
scanner := custom.NewScanner()
engine := engine.New(config, scanner)
```

## Why Gitleaks?

**Advantages:**
- **Battle-tested**: Used by thousands of projects
- **Maintained**: Active development, frequent updates
- **Comprehensive**: 200+ detection rules
- **Community**: Large ecosystem of contributed rules
- **Performance**: Written in Go, highly optimized

**Alternative Approaches Considered:**
- **Custom regex patterns**: High maintenance burden, prone to false positives
- **TruffleHog**: Similar but focuses on Git history, less artifact-focused
- **Multiple engines**: Complexity overhead, diminishing returns

**Decision**: Use Gitleaks exclusively and differentiate on artifact intelligence.

## References

- [Gitleaks GitHub](https://github.com/gitleaks/gitleaks)
- [Gitleaks Configuration](https://github.com/gitleaks/gitleaks#configuration)
- [Gitleaks Rules](https://github.com/gitleaks/gitleaks/tree/master/config)
- [Redactyl Scanner Interface](../internal/scanner/scanner.go)
- [Redactyl Gitleaks Integration](../internal/scanner/gitleaks/)
