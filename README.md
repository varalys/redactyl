# Redactyl

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Tests](https://github.com/redactyl/redactyl/actions/workflows/test.yml/badge.svg)](https://github.com/redactyl/redactyl/actions/workflows/test.yml)
[![Lint](https://github.com/redactyl/redactyl/actions/workflows/lint.yml/badge.svg)](https://github.com/redactyl/redactyl/actions/workflows/lint.yml)
[![Vuln](https://github.com/redactyl/redactyl/actions/workflows/vuln.yml/badge.svg)](https://github.com/redactyl/redactyl/actions/workflows/vuln.yml)
[![Release](https://github.com/redactyl/redactyl/actions/workflows/release.yml/badge.svg)](https://github.com/redactyl/redactyl/actions/workflows/release.yml)


Find secrets in your repo with **low noise**. Redactyl scans your working tree, staged changes, diffs, or history and reports likely credentials and tokens.

## Features

- Fast, multi‑threaded scanning with size limits and binary detection
- Targets: worktree, staged, history (last N commits), or diff vs base branch
- Detector controls: enable/disable by ID; configurable minimum confidence
- Baseline suppression file for known findings
- Outputs: table (default), JSON, SARIF 2.1.0
- Gitignore‑style path ignores via `.redactylignore`
- Clear progress, colorized severities, and summary footer (findings, duration, files scanned)
- Incremental scan cache for speed (`.redactylcache.json`)
- Config precedence: **CLI > local `.redactyl.yml` > global `~/.config/redactyl/config.yml`**
- Remediation helpers:
  - Forward fixes: remove tracked files; in‑place redaction via regex; generate `.env.example`
  - History rewrite helpers via `git filter-repo` (path, pattern, replace) with `--dry-run` and summary output
- Developer integrations: pre‑commit hook generator; GitHub Actions template
- Update experience: version printing, update checks, and self‑update command
- SARIF viewer and detector test mode
- CI‑friendly exit codes

## Table of contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Deep scanning](#deep-scanning)
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
max_archive_bytes: 33554432 # 32 MiB
max_entries: 1000
max_depth: 2
scan_time_budget: 10s
```

## Deep scanning

- Never extracts to disk; entries are streamed and filtered as text before detectors run.
- Virtual paths indicate origin inside an artifact, e.g.:
  - `archive.zip::docs/config.txt`
  - `image.tar::<layerID>/etc/app.yaml`
  - Nested: `outer.zip::inner.tgz::path/in/file.txt`
- Guardrails abort per‑artifact scanning early on size, entry count, depth, or time budgets.
- Durations use Go‑style syntax (e.g., `5s`, `2m`). Sizes are bytes.
- Artifact filenames are filtered by `.redactylignore` and include/exclude globs before opening.

Examples:

```sh
redactyl scan --archives
redactyl scan --containers --max-archive-bytes 67108864 --scan-time-budget 5s
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

Categories and example IDs (run `redactyl detectors` for the full, up‑to‑date list):

- **Cloud & DB URIs**
  - `amqp_uri_creds`, `aws_access_key`, `aws_secret_key`, `azure_storage_key`, `gcp_service_account_key`, `mongodb_uri_creds`, `mysql_uri_creds`, `postgres_uri_creds`, `redis_uri_creds`, `sqlserver_uri_creds`
- **CI/CD & developer services**
  - `docker_config_auth`, `git_credentials_url_secret`, `github_token`, `gitlab_token`, `heroku_api_key`, `npm_token`, `npmrc_auth_token`, `rubygems_credentials`, `sentry_auth_token`, `sentry_dsn`, `terraform_cloud_token`
- **Messaging & webhooks**
  - `discord_webhook`, `slack_webhook`, `slack_bot_token`, `teams_webhook`
- **Payments & fintech**
  - `coinbase_access_token`, `plaid_access_token`, `square_access_token`, `stripe_key`
- **AI & developer APIs**
  - `anthropic_api_key`, `huggingface_token`, `openai_api_key`, `replicate_api_token`
- **Telemetry & incident response**
  - `datadog_api_key`, `honeycomb_api_key`, `logdna_key`, `newrelic_api_key`, `pagerduty_api_key`, `sentry_dsn`
- **Cloud credentials & infra**
  - `aws_secret_key`, `gcp_service_account_key`, `kubeconfig`, `terraform_cloud_token`
- **Other common formats**
  - `basic_auth_header`, `bearer_token`, `jwt`, `private_key_block`, `rsa_private_key`

## How detection works

Redactyl combines pattern matching with contextual signals, structured parsing, and lightweight validators to reduce noise:

- **Context:** nearby keywords (e.g., token, secret, api\_key) and file‑type hints
- **Structured JSON/YAML:** best‑effort key/value extraction with line mapping for `.json`, `.yml`, `.yaml` (catches values even when split across lines or nested). Common keys include `openai_api_key`, `github_token`, `aws_access_key_id`, `aws_secret_access_key`, `slack_webhook`, `discord_webhook`, `stripe_secret`, `google_api_key`, `netlify_token`, `render_api_key`, `jwt`, `firebase apiKey`, `terraform token`
- **Validators:** provider‑specific prefix/length/alphabet checks and structural decoding (e.g., JWT base64url segments)

You can tune minimum confidence via `--min-confidence`. Strongly validated matches tend to score higher.

### Soft verify (optional)

`--verify safe` applies additional local‑only sanity checks after validators to further reduce noise. Examples: stricter length windows on some tokens and URL shape parsing for webhooks. No network calls or data exfiltration are performed.

## Output & Exit codes

Default table view with colors and counts. JSON and SARIF outputs are stable and documented (`docs/schemas`).

Exit codes:

- `0`: no findings or below threshold (see `--fail-on`)
- `1`: findings at or above threshold
- `2`: error while scanning

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
      - run: ./bin/redactyl scan --sarif > redactyl.sarif.json
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

## AI‑assisted development

Modern AI coding assistants (Copilot, ChatGPT, etc.) sometimes suggest realistic placeholder credentials that can accidentally get committed. Redactyl’s context‑aware detection catches both human mistakes and AI‑generated secrets that pattern‑only scanners miss.

Common AI‑generated risks:

```python
# AI assistants often suggest code like this:
openai_client = OpenAI(
    api_key="sk-1234567890abcdef..."  # Looks fake but matches real format
)
stripe.api_key = "sk_test_abc123..."   # Valid test key structure
aws_session = boto3.Session(
    aws_access_key_id="AKIA1234567890123456"  # Proper AWS key format
)
```

Traditional regex‑only scanners may miss these because they lack context. Redactyl combines pattern detection with contextual analysis to catch AI‑suggested credentials before they reach production.

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

For new detectors, please include tests with your PR (positive and negative cases). See `internal/detectors/README.md` for a short guide and template.

## Enterprise

Commercial offerings (dashboard, org policies, PR gating, SSO, hosted option) are available.

Options:

- Upload from OSS CLI to your server: `--json --upload` (see schemas in `docs/schemas/`).
- Or run scans in Enterprise workers via `github.com/redactyl/redactyl/pkg/core`.

Inquiries: open a GitHub Discussion (Q&A) titled **"Enterprise inquiry"**.

