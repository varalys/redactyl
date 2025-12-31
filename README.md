# Redactyl

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Tests](https://github.com/varalys/redactyl/actions/workflows/test.yml/badge.svg)](https://github.com/varalys/redactyl/actions/workflows/test.yml)
[![Lint](https://github.com/varalys/redactyl/actions/workflows/lint.yml/badge.svg)](https://github.com/varalys/redactyl/actions/workflows/lint.yml)
[![Vuln](https://github.com/varalys/redactyl/actions/workflows/vuln.yml/badge.svg)](https://github.com/varalys/redactyl/actions/workflows/vuln.yml)
[![Release](https://github.com/varalys/redactyl/actions/workflows/release.yml/badge.svg)](https://github.com/varalys/redactyl/actions/workflows/release.yml)

**Deep artifact scanner for cloud-native environments** - Find secrets hiding in container images, Helm charts, Kubernetes manifests, and nested archives without extracting to disk.

Powered by [Gitleaks](https://github.com/gitleaks/gitleaks) for detection, enhanced with intelligent artifact streaming and context-aware analysis.

![Redactyl TUI](docs/images/tui-screenshot.png)

## Why Redactyl?

Secrets don't just live in Git history - they hide in **container images, Helm charts, CI/CD artifacts, and nested archives** where traditional scanners can't reach them. Redactyl finds secrets in complex cloud-native artifacts without extracting them to disk.

**Key differentiators:**
- **Deep artifact scanning** - Stream archives, containers, Helm charts, and K8s manifests without disk extraction
- **Virtual paths** - Track secrets through nested artifacts: `chart.tgz::templates/secret.yaml::line-123`
- **Powered by Gitleaks** - Uses Gitleaks' detection engine; we focus on artifact intelligence
- **Privacy-first** - Zero telemetry; self-hosted friendly
- **Complete remediation** - Forward fixes and history rewriting with safety guardrails

## Table of contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Performance](#performance)
- [Configuration](#configuration)
- [Deep scanning](#deep-scanning)
- [Registry Scanning](#registry-scanning)
- [How detection works](#how-detection-works)
- [Filtering results](#filtering-results)
- [Interactive TUI](#interactive-tui)
- [Audit logging](#audit-logging)
- [Baseline](#baseline)
- [.redactylignore](#redactylignore)
- [Remediation](#remediation)
- [Output & Exit codes](#output--exit-codes)
- [CI usage](#ci-usage-github-actions)
- [Pre-commit hook](#pre-commit-hook)
- [Other CI platforms](#other-ci-platforms)
- [Privacy & Telemetry](#privacy--telemetry)
- [Public Go API](#public-go-api)
- [Updates & Changelog](#updates--changelog)
- [Versioning & Compatibility](#versioning--compatibility)
- [Acknowledgments](#acknowledgments)
- [Contributing](#contributing)
- [Enterprise](#enterprise)

## Installation

**Homebrew (macOS/Linux):**

```sh
brew install varalys/tap/redactyl
```

**Build from source:**

```sh
make build
./bin/redactyl --help
```

Or with Go directly:

```sh
go build -o bin/redactyl .
go install .  # installs to $(go env GOBIN) or $(go env GOPATH)/bin
```

Install globally (recommended):

```sh
go install github.com/varalys/redactyl@latest
redactyl --help
```

Packages (after first release): download DEB/RPM/APK from Releases and install via your package manager.

Tip: add the local `bin/` to PATH for this shell:

```sh
export PATH="$PWD/bin:$PATH"
```

## Quick start

Interactive scan (default - opens TUI):

```sh
redactyl scan
```

The TUI provides:
- Real-time findings with severity color-coding
- Vim-style navigation with search, filter, and grouping
- Syntax-highlighted context preview
- Quick actions: open in editor, baseline, ignore, export
- Virtual file extraction from archives
- Diff view to compare scans

Non-interactive scan (for CI/CD):

```sh
redactyl scan --no-tui
```

With guidance (suggested remediation commands):

```sh
redactyl scan --guide --no-tui
```

JSON output:

```sh
redactyl scan --json  # Auto-disables TUI
```

SARIF output:

```sh
redactyl scan --sarif > redactyl.sarif.json  # Auto-disables TUI
```

Text‑only format:

```sh
redactyl scan --text --no-tui
```

Scope control:

```sh
redactyl scan --staged                 # staged changes only
redactyl scan --history 5              # last N commits
redactyl scan --base main              # diff vs base branch
```

Performance tuning:

```sh
redactyl scan --threads 4 --max-bytes 2097152
```

## Performance

Redactyl is designed for speed. Typical scan times:

- **Helm chart (50 templates):** ~2-5ms
- **Container image (100MB):** ~100-200ms
- **Nested archives:** ~10-20ms overhead per level
- **CI/CD full scan:** ~1-2 seconds for typical projects

**Throughput:** 100-500 MB/s for archives, 8-10 MB/s for YAML parsing

Fast enough for pre-commit hooks and CI/CD pipelines.

See [detailed benchmarks](internal/artifacts/BENCHMARKS.md) for complete performance analysis.

## Configuration

Redactyl reads configuration in order of precedence (highest first):

1. CLI flags
2. Local file: `.redactyl.yml` at repo root
3. Global file: `~/.config/redactyl/config.yml`

Key fields include `include`, `exclude`, `max_bytes`, `threads`, `enable`, `disable`, `min_confidence`, `no_color`, etc.

### Generate a config

Starter config (default preset):

```sh
redactyl config init
```

Minimal preset (critical detectors only):

```sh
redactyl config init --preset minimal --min-confidence 0.85
```

Custom selection via `--enable`/`--disable`:

```sh
redactyl config init --enable "aws_access_key,aws_secret_key,private_key_block,github_token,openai_api_key"
```

**Example `.redactyl.yml`:**

```yaml
enable: aws_access_key,aws_secret_key,private_key_block,github_token,jwt
max_bytes: 1048576
threads: 0
min_confidence: 0.85
default_excludes: true
no_color: false
# Optional deep scanning toggles and limits
archives: false
containers: false
iac: false
helm: false        # Scan Helm charts (.tgz and directories)
k8s: false         # Scan Kubernetes manifests (YAML)
max_archive_bytes: 33554432 # 32 MiB
max_entries: 1000
max_depth: 2
scan_time_budget: 10s
global_artifact_budget: 10s

# Gitleaks integration (optional custom config)
gitleaks:
  config: .gitleaks.toml    # Path to custom Gitleaks config
  auto_download: true        # Auto-download Gitleaks if not found
  version: latest            # Gitleaks version to use
```

## Deep scanning

Scan cloud-native artifacts with configurable guardrails:

**Supported types:**
- Archives (zip, tar, tgz), nested archives
- Container images (Docker tarballs, OCI format)
- Helm charts (.tgz and directories)
- Kubernetes manifests (YAML)
- IaC files (Terraform state, kubeconfigs)

**Usage:**

```sh
# Scan archives
redactyl scan --archives

# Scan container images
redactyl scan --containers

# Scan Helm charts (both .tgz and directories)
redactyl scan --helm

# Scan Kubernetes manifests
redactyl scan --k8s

# Scan everything with guardrails
redactyl scan --archives --containers --helm --k8s \
  --max-archive-bytes 67108864 \
  --max-depth 3 \
  --scan-time-budget 10s \
  --global-artifact-budget 30s
```

## Registry Scanning

Redactyl can scan remote container images directly from OCI-compliant registries (Docker Hub, GCR, ECR, ACR, etc.) without pulling them to disk.

**Usage:**

```sh
# Scan public image
redactyl scan --registry alpine:latest

# Scan private image (Google Container Registry)
redactyl scan --registry gcr.io/my-project/my-app:v1.0.1

# Scan multiple images
redactyl scan --registry image1:tag --registry image2:tag
```

**Authentication:**

Redactyl automatically uses your local Docker credentials (from `~/.docker/config.json` or credential helpers). If you can run `docker pull`, you can run `redactyl scan --registry`.

- **CI/CD:** Ensure `docker login` is run before the scan, or provide a config file with credentials.
- **Cloud Providers:** Standard helpers (e.g., `docker-credential-gcr`, `docker-credential-ecr-login`) are supported.

**How it works:**

1. Fetches image manifest and metadata (lightweight).
2. Streams image layers directly into memory.
3. Scans file contents on-the-fly using Gitleaks.
4. Reports findings with virtual paths: `registry.example.com/image:tag::sha256:layerhash/path/to/secret`.

This approach is significantly faster and uses less disk space than pulling full images.

## Baseline

Update the baseline from current scan results:

```sh
redactyl baseline update
```

- File: `redactyl.baseline.json`
- Suppresses previously recorded findings; only new findings are reported.

## .redactylignore

Create `.redactylignore` at your repo root (gitignore syntax). Example:

```
# node artifacts
node_modules/
dist/
*.min.js

# test data
testdata/**
```

- Paths matching this file are skipped.
- By default, Redactyl excludes common noisy artifacts and generated files (configurable): lockfiles (e.g., `yarn.lock`), binaries (`*.wasm`, `*.pyc`), large archives, and generated code (`*.pb.go`, `*.gen.*`). Use `--include/--exclude` and `.redactylignore` to override.
- For deep scanning, artifact filenames (e.g., `*.zip`, `*.tar`) are filtered by `.redactylignore` and include/exclude globs before the archive/container is opened.

## Remediation

**Forward‑only fixes (safe defaults):**

- Remove a tracked file and ignore it:
  ```sh
  redactyl fix path .env --add-ignore
  ```
- Redact secrets in‑place using regex and commit (optionally record a summary file):
  ```sh
  redactyl fix redact --file app.yaml --pattern 'password:\s*\S+' --replace 'password: <redacted>' --summary remediation.json
  ```
- Generate/update `.env.example` from `.env` and ensure `.env` is ignored:
  ```sh
  redactyl fix dotenv --from .env --to .env.example --add-ignore
  ```

**History rewrite (dangerous; creates a backup branch; you likely must force‑push):**

- Remove a single path from all history (with a summary file to audit in CI):
  ```sh
  redactyl purge path secrets.json --yes --backup-branch my-backup --summary remediation.json
  ```
- Remove by glob pattern(s):
  ```sh
  redactyl purge pattern --glob '**/*.pem' --glob '**/*.key' --yes
  ```
- Replace content across history using a `git filter-repo` replace‑text file:
  ```sh
  redactyl purge replace --replacements replacements.txt --yes
  ```
- Add `--dry-run` to print the exact commands without executing, and `--summary purge.json` to write a small remediation summary JSON you can parse in CI.

## Filtering results

Redactyl uses Gitleaks' detection rules. Filter findings by Gitleaks rule IDs:

```sh
# Show only specific rule IDs
redactyl scan --enable "github-pat,aws-access-key,private-key"

# Exclude specific rule IDs
redactyl scan --disable "generic-api-key"

# List common rule IDs
redactyl detectors
```

**Note:** These flags filter results after scanning. To configure Gitleaks rules themselves, use a `.gitleaks.toml` file (see [How detection works](#how-detection-works)).

## Interactive TUI

Redactyl provides a rich terminal user interface (TUI) for interactive secret scanning and management.

### Features

- **Visual findings table** - Color-coded severity (High/Medium/Low)
- **Detailed view** - Full context with syntax highlighting
- **Quick actions:**
  - `o` / `Enter` - Open file in `$EDITOR` at exact line and column
  - `i` / `I` - Add/remove file from `.redactylignore`
  - `b` / `U` - Add/remove finding from baseline
  - `r` - Rescan (fresh scan without cache)
  - `e` - Export current view (JSON/CSV/SARIF)
  - `y` / `Y` - Copy path / full details to clipboard
  - `R` - Toggle raw audit logging (opt-in; default is redacted)
- **Navigation:**
  - `j` / `k` - Move through findings
  - `Ctrl+d` / `Ctrl+u` - Half-page down/up
  - `g` / `G` - Jump to top/bottom
  - `n` / `N` - Jump to next/previous HIGH severity finding
- **Search & Filter:**
  - `/` - Search by path, detector, or match text
  - `1` / `2` / `3` - Filter by HIGH/MED/LOW severity
  - `s` / `S` - Cycle sort column / reverse sort
  - `Esc` - Clear all filters
- **Grouping:**
  - `gf` - Group findings by file path
  - `gd` - Group findings by detector type
  - `Tab` - Expand/collapse groups
- **Selection & Bulk:**
  - `v` - Toggle selection on current finding
  - `V` - Select/deselect all visible findings
  - `B` - Bulk baseline all selected
  - `Ctrl+i` - Bulk ignore all selected files
- **Context:**
  - `+` / `-` - Show more/fewer context lines around finding
  - Git commit info displayed when available
- **Diff View:**
  - `D` - Compare current scan vs previous scan
  - Shows new findings (red) and fixed findings (green)
- **Virtual Files:**
  - Findings inside archives show file breakdown
  - Press `o` to extract to temp and open in editor
- **Scan History:**
  - `a` - View audit log history
  - Load and review previous scans

### Usage

The TUI opens automatically by default:

```sh
redactyl scan
```

To disable (for scripts/CI/CD):

```sh
redactyl scan --no-tui
```

View last scan results without rescanning:

```sh
redactyl scan --view-last
```

The TUI automatically disables when:
- Output is piped: `redactyl scan | grep something`
- `--json` or `--sarif` flags are used
- stdout is not a terminal

### Keyboard shortcuts

Press `?` or `h` in the TUI to see all keyboard shortcuts.

## Audit logging

Redactyl automatically maintains an audit log of all scans for compliance and reporting purposes.

Audit logs are **redacted by default** (no raw match/secret values). To opt in to storing raw values, toggle `R` in the TUI and re-run scans.

### Log location

- `.git/redactyl_audit.jsonl` (if in a Git repository)
- `.redactyl_audit.jsonl` (otherwise)

### Log format

JSON Lines format (one JSON object per line) for easy parsing:

```json
{
  "timestamp": "2025-11-24T15:41:43.103433-07:00",
  "scan_id": "scan_1764024103",
  "root": "/Users/user/project",
  "total_findings": 130,
  "new_findings": 12,
  "baselined_count": 118,
  "severity_counts": {
    "high": 116,
    "medium": 13,
    "low": 1
  },
  "files_scanned": 163,
  "duration": "302ms",
  "baseline_file": "redactyl.baseline.json",
  "top_findings": [
    {
      "path": "cmd/app/main.go",
      "detector": "generic-api-key",
      "severity": "high",
      "line": 42
    }
  ]
}
```

### Usage for auditing

View all audit logs:

```sh
cat .git/redactyl_audit.jsonl | jq .
```

Count total scans:

```sh
wc -l .git/redactyl_audit.jsonl
```

Filter scans with high-severity findings:

```sh
cat .git/redactyl_audit.jsonl | jq 'select(.severity_counts.high > 0)'
```

Export for compliance report:

```sh
cp .git/redactyl_audit.jsonl audit_trail_$(date +%Y%m%d).jsonl
```

Generate summary report:

```sh
cat .git/redactyl_audit.jsonl | jq -r '[.timestamp, .total_findings, .new_findings] | @csv'
```

### Benefits

- **Immutable trail** - Append-only log ensures scan history is preserved
- **Compliance ready** - Structured format suitable for SOC2, ISO 27001, and other audits
- **Timestamped** - Every scan recorded with precise timestamp
- **Severity tracking** - Monitor high/medium/low findings over time
- **Baseline tracking** - Shows which findings are accepted vs new
- **Sample findings** - Top 10 new findings included for quick reference
- **Performance metrics** - Duration and files scanned tracked

## How detection works

Redactyl uses Gitleaks as its detection engine, enhanced with artifact-aware intelligence:

1. **Artifact Streaming:** Archives and containers are streamed without disk extraction
2. **Virtual Path Mapping:** Track secrets through nested artifacts (e.g., `chart.tgz::templates/secret.yaml`)
3. **Gitleaks Detection:** Content scanned using Gitleaks' detection rules
4. **Context Enhancement:** Structured JSON/YAML parsing adds line mapping and field context
5. **Result Aggregation:** Findings include both Gitleaks metadata and artifact context

Configure detection rules using standard Gitleaks `.gitleaks.toml` files:

```toml
# .gitleaks.toml
[extend]
useDefault = true

[[rules]]
id = "custom-api-key"
description = "Custom API Key"
regex = '''my-custom-pattern'''

[allowlist]
paths = ["**/*.example", "**/test/**"]
```

See [Gitleaks configuration docs](https://github.com/gitleaks/gitleaks#configuration) for details.

## Output & Exit codes

Default table view with colors and counts. JSON and SARIF outputs are stable and documented (`docs/schemas`).

Schema stability:

- Default JSON (`--json`) remains a stable array across v1.
- Extended JSON (`--json --json-extended`) is additive and versioned via `schema_version` (currently "1").
- SARIF remains 2.1.0; optional `run.properties.artifactStats` is present when deep scanning is enabled.

Exit codes:

- `0`: no findings or below threshold (see `--fail-on`)
- `1`: findings at or above threshold
- `2`: error while scanning

JSON shape:

- By default, `--json` emits an array of findings.
- For extended metadata, use `--json --json-extended` to emit an object with a schema version, findings, and artifact stats:

```json
{
  "schema_version": "1",
  "findings": [ /* ... */ ],
  "artifact_stats": { "bytes": 0, "entries": 0, "depth": 0, "time": 0 }
}
```

SARIF notes:

- SARIF 2.1.0 is written via `--sarif`. Artifact stats are included in `runs[0].properties.artifactStats`.

CLI footer:

- When deep scanning is enabled and any artifact limits are hit, a brief footer is printed with counters, e.g.:

```
Artifact limits: bytes=1 entries=0 depth=0 time=0
```

## CI usage (GitHub Actions)

```yaml
name: Redactyl Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: 'stable'
      - run: go build -o bin/redactyl .
      - run: ./bin/redactyl scan --sarif --archives --global-artifact-budget 15s > redactyl.sarif.json
        # Note: --sarif automatically disables TUI, but --no-tui can be explicit
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: redactyl.sarif.json
      - name: Upload audit log
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: redactyl-audit-log
          path: .git/redactyl_audit.jsonl
```

## Pre-commit hook

```sh
redactyl hook install --pre-commit
```

Or use the [pre-commit framework](https://pre-commit.com):

```yaml
- repo: https://github.com/varalys/redactyl
  rev: v1.0.1
  hooks:
    - id: redactyl-scan
```

## Other CI platforms

Generate templates for GitLab, Bitbucket, or Azure DevOps:

```sh
redactyl ci init --provider gitlab    # or bitbucket, azure
redactyl action init                   # GitHub Action
```

## Privacy & Telemetry

No telemetry by default. Optional upload via `--upload` can omit repo metadata with `--no-upload-metadata`.

## Public Go API

Stable API surface for external consumers:

- Import `github.com/varalys/redactyl/pkg/core`
- Types: `core.Config`, `core.Finding`
- Entry point: `core.Scan(cfg)`

## Updates & Changelog

- A check for newer versions is displayed on scan (can be disabled via flags/config).
- Update in‑place from GitHub Releases:
  ```sh
  redactyl update
  ```
- See `CHANGELOG.md` for notable changes.

## Versioning & Compatibility

Semantic Versioning (SemVer):

- **CLI:** additive flags and outputs are minor; breaking changes bump major.
- **JSON output:** backwards‑compatible field additions are minor; removing/renaming fields is major.
- **SARIF:** remains compliant with v2.1.0; optional fields (e.g., `helpUri`) may be added without breaking consumers.
- **Rule IDs:** stable; renames or removals are major. New rule IDs may be added in any minor.
- **Public Go API (`pkg/core`)**: follows SemVer; breaking changes require a major version.

## Acknowledgments

Built with [Gitleaks](https://github.com/gitleaks/gitleaks) for secret detection, [Bubbletea](https://github.com/charmbracelet/bubbletea) and the [Charm](https://charm.sh) stack for the TUI, [go-containerregistry](https://github.com/google/go-containerregistry) for OCI support, [go-git](https://github.com/go-git/go-git) for Git operations, and [Chroma](https://github.com/alecthomas/chroma) for syntax highlighting.

## License

Apache‑2.0. See [`LICENSE`](LICENSE).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

Redactyl uses Gitleaks for all secret detection. To add new detection rules, contribute to the [Gitleaks project](https://github.com/gitleaks/gitleaks) or create custom rules in `.gitleaks.toml`.

**AI Contributions:** We welcome contributions assisted by AI tools (LLMs, Copilot, etc.), provided they meet our quality standards, follow project conventions, and include comprehensive tests. The submitter is responsible for the correctness and security of the code.

## Enterprise

Commercial offerings (dashboard, org policies, PR gating, SSO, hosted option) are available.

Options:

- Upload from OSS CLI to your server: `--json --upload` (see schemas in `docs/schemas/`).
- Or run scans in Enterprise workers via `github.com/varalys/redactyl/pkg/core`.

Inquiries: open a GitHub Discussion (Q&A) titled **"Enterprise inquiry"**.
