# Redactyl

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Tests](https://github.com/redactyl/redactyl/actions/workflows/test.yml/badge.svg)](https://github.com/redactyl/redactyl/actions/workflows/test.yml)
[![Lint](https://github.com/redactyl/redactyl/actions/workflows/lint.yml/badge.svg)](https://github.com/redactyl/redactyl/actions/workflows/lint.yml)
[![Vuln](https://github.com/redactyl/redactyl/actions/workflows/vuln.yml/badge.svg)](https://github.com/redactyl/redactyl/actions/workflows/vuln.yml)
[![Release](https://github.com/redactyl/redactyl/actions/workflows/release.yml/badge.svg)](https://github.com/redactyl/redactyl/actions/workflows/release.yml)

**Deep artifact scanner for cloud-native environments** - Find secrets hiding in container images, Helm charts, Kubernetes manifests, and nested archives without extracting to disk.

Powered by [Gitleaks](https://github.com/gitleaks/gitleaks) for detection, enhanced with intelligent artifact streaming and context-aware analysis.

## Why Redactyl?

Secrets don't just live in your Git history - they hide in **container images, Helm charts, CI/CD artifacts, and nested archives** where traditional scanners can't reach them.

### What Makes Redactyl Different

**🔍 Deep Artifact Intelligence**
- Scans **inside archives and containers** without extracting to disk (streaming)
- Supports: zip, tar, tgz, Docker images, Helm charts, Kubernetes manifests
- **Virtual paths** show exactly where secrets hide: `myapp.tar::layer-abc123::etc/config.yaml`
- Handles nested artifacts (e.g., zip inside tar inside container)

**🚀 Cloud-Native First**
- Built for DevSecOps teams working with Kubernetes and containers
- Scans Helm charts, K8s manifests, Terraform state files
- IaC hotspot detection for infrastructure-as-code secrets
- Future: registry integration, scan-on-push webhooks

**💪 Powered by Gitleaks**
- Leverages [Gitleaks'](https://github.com/gitleaks/gitleaks) 700+ detection rules
- Standard `.gitleaks.toml` configuration
- Focuses our innovation on artifact complexity, not regex maintenance

**🔒 Privacy-First**
- Zero telemetry by default
- Self-hosted friendly
- Optional upload for enterprise dashboards (explicit opt-in)

**🛠️ Complete Remediation Suite**
- Forward fixes: remove tracked files, redact in-place, generate `.env.example`
- History rewriting: purge secrets from Git history with safety guardrails
- Dry-run mode and audit trails

## Features

**Artifact Scanning**
- Stream archives (zip, tar, tgz) without disk extraction
- Docker container image layer scanning with context
- Helm chart and Kubernetes manifest analysis
- Terraform state file inspection
- Nested artifact support with configurable depth limits
- Guardrails: size, entry count, depth, time budgets

**Detection & Analysis**
- Powered by Gitleaks detection engine (700+ rules)
- Context-aware structured JSON/YAML parsing
- Virtual paths preserve artifact origin chains
- Multiple output formats: table, JSON, SARIF 2.1.0

**Developer Experience**
- Fast multi-threaded scanning
- Incremental cache for unchanged files
- Pre-commit hooks and CI/CD templates
- Clear progress indicators and colorized output
- Config precedence: CLI > local `.redactyl.yml` > global config

**Enterprise Ready**
- SARIF output for GitHub Code Scanning
- JSON upload to custom dashboards
- Public Go API (`pkg/core`) for integrations
- Baseline suppression for known findings
- Audit-friendly summary outputs

## Table of contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Deep scanning](#deep-scanning)
  - See the Deep scanning guide: [`docs/deep-scanning.md`](docs/deep-scanning.md)
- [Detectors](#detectors)
- [How detection works](#how-detection-works)
- [Baseline](#baseline)
- [.redactylignore](#redactylignore)
- [Remediation](#remediation)
- [Output & Exit codes](#output--exit-codes)
- [CI usage](#ci-usage-github-actions)
- [Pre-commit hook](#pre-commit-hook)
- [GitHub Action template](#github-action-template)
- [Other CI templates](#other-ci-templates)
- [Privacy & Telemetry](#privacy--telemetry)
- [AI‑assisted development](#ai-assisted-development)
- [Public Go API](#public-go-api)
- [Updates & Changelog](#updates--changelog)
- [Versioning & Compatibility](#versioning--compatibility)
- [License](#license)
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

Redactyl excels at finding secrets in complex cloud-native artifacts without extracting them to disk.

**Supported Artifact Types:**
- **Archives**: zip, tar, tgz, tar.gz (nested archives supported)
- **Container Images**: Docker saved tarballs with full layer scanning
- **Helm Charts**: `.tgz` archives and unpacked chart directories (Chart.yaml, values.yaml, templates/)
- **Kubernetes Manifests**: YAML files with Secrets, ConfigMaps, Deployments, etc.
- **IaC Files**: Terraform state files, kubeconfigs

**Key Features:**
- **Streaming** - Never extracts to disk; entries are streamed and filtered as text
- **Virtual Paths** - Show exactly where secrets hide:
  - `archive.zip::docs/config.txt`
  - `image.tar::layer-abc123::etc/app.yaml`
  - `my-chart.tgz::templates/secret.yaml`
  - `outer.zip::inner.tgz::nested/file.txt`
- **Guardrails** - Abort per-artifact on size, entry count, depth, or time budgets
- **Global Budget** - Cap total scan time across all artifacts
- **Smart Filtering** - Artifact filenames filtered by `.redactylignore` and globs before opening

**Examples:**

```sh
# Scan archives
redactyl scan --archives

# Scan container images
redactyl scan --containers

# Scan Helm charts (both .tgz and directories)
redactyl scan --helm

# Scan Kubernetes manifests
redactyl scan --k8s

# Combine multiple types
redactyl scan --containers --helm --k8s --archives

# With guardrails
redactyl scan --helm --k8s \
  --max-archive-bytes 67108864 \
  --scan-time-budget 5s \
  --global-artifact-budget 30s
```

**Cloud-Native Project Scanning:**

```sh
# Typical Kubernetes project
redactyl scan --helm --k8s -p ./k8s-deployments

# Full CI/CD artifact scan
redactyl scan --archives --containers --helm --k8s \
  --max-depth 3 \
  --scan-time-budget 10s
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

## Detectors

List available IDs:

```sh
redactyl detectors
```

Enable only specific detectors:

```sh
redactyl scan --enable "twilio,github_token"
```

Disable specific detectors:

```sh
redactyl scan --disable "entropy_context"
```

<!-- BEGIN:DETECTORS_CATEGORIES -->

Categories and example IDs (run `redactyl detectors` for the full, up-to-date list):

- AI providers:
  - anthropic-api-key, openai-api-key
- Other common services:
  - aws-access-key, aws-mws-key, aws-secret-key, docker-config-auth, gcp-service-account, generic-api-key, github-app-token, github-fine-grained-pat, github-oauth, github-pat, gitlab-pat, gitlab-pipeline-token, gitlab-runner-token, google-api-key, google-oauth, jwt, npm-access-token, private-key, pypi-token, sendgrid-api-key, slack-app-token, slack-bot-token, slack-webhook-url, stripe-access-token, stripe-secret-key
<!-- END:DETECTORS_CATEGORIES -->

## How detection works

Redactyl uses **Gitleaks** as its detection engine, enhanced with artifact-aware intelligence:

### Detection Flow

1. **Artifact Streaming:** Archives and containers are streamed without disk extraction
2. **Virtual Path Mapping:** Each entry gets a virtual path showing its origin (e.g., `image.tar::layer-abc::etc/config.yaml`)
3. **Gitleaks Detection:** Content is scanned using Gitleaks' 700+ detection rules
4. **Context Enhancement:** Structured JSON/YAML parsing adds line mapping and field context
5. **Result Aggregation:** Findings include both Gitleaks metadata and artifact context

### Configuration

Detection rules are configured using standard Gitleaks `.gitleaks.toml` files:

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

See [Gitleaks configuration docs](https://github.com/gitleaks/gitleaks#configuration) for full details.

### Structured Parsing Enhancement

Beyond Gitleaks' regex matching, Redactyl adds:

- **JSON/YAML parsing:** Extracts key/value pairs with line mapping
- **Artifact context:** Shows which layer, archive entry, or manifest contains the secret
- **Nested detection:** Finds secrets in deeply nested structures that span multiple lines

Common structured keys detected: `openai_api_key`, `github_token`, `aws_access_key_id`, `aws_secret_access_key`, `slack_webhook`, `discord_webhook`, `stripe_secret`, `kubernetes.io/dockerconfigjson`

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

Install directly:

```sh
redactyl hook install --pre-commit
```

Or via the pre-commit framework:

```yaml
- repo: https://github.com/redactyl/redactyl
  rev: v0.1.0
  hooks:
    - id: redactyl-scan
```

## GitHub Action template

```sh
redactyl action init
```

## Other CI templates

- GitLab CI: see `docs/ci/gitlab-ci.yml`
- Bitbucket Pipelines: see `docs/ci/bitbucket-pipelines.yml`
- Azure DevOps: see `docs/ci/azure-pipelines.yml`

Generate into your repo:

```sh
redactyl ci init --provider gitlab
redactyl ci init --provider bitbucket
redactyl ci init --provider azure
```

## Privacy & Telemetry

- No code or findings are sent anywhere by default. There is **no telemetry**.
- Optional upload is explicit via `--upload` and can omit repo metadata with `--no-upload-metadata`.

## Use Cases

### Container Security
```bash
# Scan Docker images before pushing to registry
docker save myapp:latest | redactyl scan --containers -

# Scan all images in a build directory
redactyl scan --containers ./build/images/
```

### Kubernetes & Helm
```bash
# Scan Helm charts for embedded secrets
redactyl scan --helm ./charts/myapp

# Scan Kubernetes manifests
redactyl scan --kubernetes ./k8s/

# Scan before applying to cluster
kubectl kustomize ./overlays/prod | redactyl scan --kubernetes -
```

### CI/CD Pipelines
```bash
# Scan build artifacts before deployment
redactyl scan --archives ./dist/ --global-artifact-budget 2m

# Scan Terraform state files
redactyl scan --terraform ./terraform/*.tfstate
```

### AI-Assisted Development

Modern AI coding assistants (Copilot, ChatGPT, etc.) sometimes suggest realistic placeholder credentials. Redactyl (via Gitleaks) catches these before they reach production:

```python
# AI assistants often suggest code like this:
openai_client = OpenAI(
    api_key="sk-1234567890abcdef..."  # Looks fake but matches real format
)
stripe.api_key = "sk_test_abc123..."   # Valid test key structure
```

Combined with artifact scanning, you catch secrets in both code and deployment artifacts.

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

