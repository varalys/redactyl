# Redactyl

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Tests](https://github.com/redactyl/redactyl/actions/workflows/test.yml/badge.svg)](https://github.com/redactyl/redactyl/actions/workflows/test.yml)
[![Lint](https://github.com/redactyl/redactyl/actions/workflows/lint.yml/badge.svg)](https://github.com/redactyl/redactyl/actions/workflows/lint.yml)
[![Vuln](https://github.com/redactyl/redactyl/actions/workflows/vuln.yml/badge.svg)](https://github.com/redactyl/redactyl/actions/workflows/vuln.yml)
[![Release](https://github.com/redactyl/redactyl/actions/workflows/release.yml/badge.svg)](https://github.com/redactyl/redactyl/actions/workflows/release.yml)

**Deep artifact scanner for cloud-native environments** - Find secrets hiding in container images, Helm charts, Kubernetes manifests, and nested archives without extracting to disk.

Powered by [Gitleaks](https://github.com/gitleaks/gitleaks) for detection, enhanced with intelligent artifact streaming and context-aware analysis.

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
- [How detection works](#how-detection-works)
- [Filtering results](#filtering-results)
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
- [Contributing](#contributing)
- [Enterprise](#enterprise)

## Installation

> If you built locally, replace `redactyl` with `./bin/redactyl` in all commands below.

Build from source (repo root):

```sh
make build
redactyl --help
```

Or with Go directly:

```sh
go build -o bin/redactyl .
go install .  # installs to $(go env GOBIN) or $(go env GOPATH)/bin
```

Install globally (recommended):

```sh
go install github.com/redactyl/redactyl@latest
redactyl --help
```

Packages (after first release): download DEB/RPM/APK from Releases and install via your package manager.

Tip: add the local `bin/` to PATH for this shell:

```sh
export PATH="$PWD/bin:$PATH"
```

## Quick start

Default scan:

```sh
redactyl scan
```

With guidance (suggested remediation commands):

```sh
redactyl scan --guide
```

JSON output:

```sh
redactyl scan --json
```

SARIF output:

```sh
redactyl scan --sarif > redactyl.sarif.json
```

Text‑only format:

```sh
redactyl scan --text
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

# Combine all artifact types with guardrails
redactyl scan --archives --containers --helm --k8s \
  --max-archive-bytes 67108864 \
  --max-depth 3 \
  --scan-time-budget 10s \
  --global-artifact-budget 30s
```

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
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: redactyl.sarif.json
```

## Pre-commit hook

```sh
redactyl hook install --pre-commit
```

Or use the [pre-commit framework](https://pre-commit.com):

```yaml
- repo: https://github.com/redactyl/redactyl
  rev: v0.1.0
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

- Import `github.com/redactyl/redactyl/pkg/core`
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

## License

Apache‑2.0. See [`LICENSE`](LICENSE).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

Redactyl uses Gitleaks for all secret detection. To add new detection rules, contribute to the [Gitleaks project](https://github.com/gitleaks/gitleaks) or create custom rules in `.gitleaks.toml`.

## Enterprise

Commercial offerings (dashboard, org policies, PR gating, SSO, hosted option) are available.

Options:

- Upload from OSS CLI to your server: `--json --upload` (see schemas in `docs/schemas/`).
- Or run scans in Enterprise workers via `github.com/redactyl/redactyl/pkg/core`.

Inquiries: open a GitHub Discussion (Q&A) titled **"Enterprise inquiry"**.

