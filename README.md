## Redactyl

![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)

[![Tests](https://github.com/redactyl/redactyl/actions/workflows/test.yml/badge.svg)](https://github.com/redactyl/redactyl/actions/workflows/test.yml)
[![Lint](https://github.com/redactyl/redactyl/actions/workflows/lint.yml/badge.svg)](https://github.com/redactyl/redactyl/actions/workflows/lint.yml)
[![Vuln](https://github.com/redactyl/redactyl/actions/workflows/vuln.yml/badge.svg)](https://github.com/redactyl/redactyl/actions/workflows/vuln.yml)

[![Release](https://github.com/redactyl/redactyl/actions/workflows/release.yml/badge.svg)](https://github.com/redactyl/redactyl/actions/workflows/release.yml)

Find secrets in your repo with low noise. Redactyl scans your working tree, staged changes, diffs, or history and reports likely credentials and tokens.

### Features
- Fast multi-threaded scanning with size limits and binary detection
- Worktree, staged, history (last N commits), or diff vs base branch
- Detector enable/disable controls
- Baseline file to suppress known findings
- Outputs: table (default), JSON, SARIF 2.1.0
- Gitignore-style path ignores via `.redactylignore`
- Progress display and colorized severities; summary footer (findings, duration, files scanned)
- Incremental scan cache for speed (`.redactylcache.json`)
- Config file support with precedence: CLI > local `.redactyl.yml` > global `~/.config/redactyl/config.yml`
- Remediation:
  - Forward fixes: remove tracked files; redact in-place via regex; generate `.env.example`
  - History rewrite helpers via `git filter-repo` (path, pattern, replace) with `--dry-run` and summary output
- Developer integrations: pre-commit hook generator; GitHub Actions template
- Update experience: version printing, update checks, and self-update command
- SARIF viewer and detector test mode
- CI-friendly exit codes

### Privacy & Telemetry
- No code or findings are sent anywhere by default. There is no telemetry.
- Optional upload is explicit via `--upload` and can omit repo metadata with `--no-upload-metadata`.

### AI-assisted development
- Modern AI coding assistants (Copilot, ChatGPT, etc.) frequently suggest realistic placeholder credentials that can accidentally get committed
- Redactyl's context-aware detection catches both human mistakes and AI-generated secrets that traditional pattern-only scanners miss
- Protects against AI-suggested keys that match real service formats but appear harmless in isolation

Common AI-generated risks:
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
- Traditional regex-only scanners may miss these because they lack context
- Redactyl combines pattern detection with contextual analysis to catch AI-suggested credentials before they reach production

### Install
- Build locally (repo root):
  ```sh
  make build
  ./bin/redactyl --help
  ```
- Or:
  ```sh
  go build -o bin/redactyl .
  go install .  # installs to $(go env GOBIN) or $(go env GOPATH)/bin
  ```

- Install globally (recommended):
  ```sh
  go install github.com/redactyl/redactyl@latest
  # then use the binary directly if your GOBIN is on PATH
  redactyl --help
  ```

- DEB/RPM/APK (after first release): download from Releases and install via your package manager.

- Tip: to use the locally built binary without typing ./bin/, add it to PATH for this shell:
  ```sh
  export PATH="$PWD/bin:$PATH"
  ```

### Quick start
- Default scan:
  ```sh
  ./bin/redactyl scan
  ```
  If installed globally:
  ```sh
  redactyl scan
  ```
- With guidance (suggested remediation commands):
  ```sh
  ./bin/redactyl scan --guide
  ```
  If installed globally:
  ```sh
  redactyl scan --guide
  ```
- JSON:
  ```sh
  ./bin/redactyl scan --json
  ```
  If installed globally:
  ```sh
  redactyl scan --json
  ```
- SARIF:
  ```sh
  ./bin/redactyl scan --sarif > redactyl.sarif.json
  ```
  If installed globally:
  ```sh
  redactyl scan --sarif > redactyl.sarif.json
  ```
- Text format:
  ```sh
  ./bin/redactyl scan --text
  ```
  If installed globally:
  ```sh
  redactyl scan --text
  ```
- Staged changes only:
  ```sh
  ./bin/redactyl scan --staged
  ```
- Last N commits:
  ```sh
  ./bin/redactyl scan --history 5
  ```
- Diff vs base branch:
  ```sh
  ./bin/redactyl scan --base main
  ```
- Performance:
  ```sh
  ./bin/redactyl scan --threads 4 --max-bytes 2097152
  ```

### Config
- Redactyl reads configuration from, in order of precedence (highest first):
  1) CLI flags
  2) Local file: `.redactyl.yml` at repo root
  3) Global file: `~/.config/redactyl/config.yml`
- Fields include `include`, `exclude`, `maxBytes`, `threads`, `enable`, `disable`, `minConfidence`, `noColor`, etc.

#### Generate a config
- Create a starter config with all detectors enabled (default preset is standard):
  ```sh
  ./bin/redactyl config init
  ```
- Minimal preset (critical detectors only):
  ```sh
  ./bin/redactyl config init --preset minimal --min-confidence 0.85
  ```
- Custom selection via `--enable`/`--disable`:
  ```sh
  ./bin/redactyl config init --enable "aws_access_key,aws_secret_key,private_key_block,github_token,openai_api_key"
  ```

Example `.redactyl.yml`:
```yaml
enable: aws_access_key,aws_secret_key,private_key_block,github_token,jwt
max_bytes: 1048576
threads: 0
min_confidence: 0.85
default_excludes: true
no_color: false
```

### Baseline
- Update the baseline from the current scan results:
  ```sh
  ./bin/redactyl baseline update
  ```
- Baseline file: `redactyl.baseline.json`
- The baseline suppresses previously recorded findings; only new findings are reported.

### Ignoring paths
- Create `.redactylignore` at your repo root (gitignore syntax). Example:
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

### Inline suppressions
- Suppress a single line for any detector:
  ```
  password = "not_a_real_secret"  # redactyl:ignore
  ```
- Suppress only the next line:
  ```
  # redactyl:ignore-next-line
  api_key = "sk_test_not_real"
  ```
- Suppress a region:
  ```
  # redactyl:ignore-start
  ... lines ...
  # redactyl:ignore-end
  ```
Notes:
- Region and next-line ignores apply regardless of detector ID.
- The legacy `redactyl:ignore` continues to work and can be paired with a provider substring on the same line.

### Remediation
- Forward-only fixes (safe defaults):
  - Remove a tracked file and ignore it:
    ```sh
    ./bin/redactyl fix path .env --add-ignore
    ```
  - Redact secrets in-place using regex and commit (optionally record a summary file):
    ```sh
    ./bin/redactyl fix redact --file app.yaml --pattern 'password:\s*\S+' --replace 'password: <redacted>' --summary remediation.json
    ```
  - Generate/update `.env.example` from `.env` and ensure `.env` is ignored:
    ```sh
    ./bin/redactyl fix dotenv --from .env --to .env.example --add-ignore
    ```
- History rewrite (dangerous; creates a backup branch; you likely must force-push):
  - Remove a single path from all history (with a summary file to audit in CI):
    ```sh
    ./bin/redactyl purge path secrets.json --yes --backup-branch my-backup --summary remediation.json
    ```
  - Remove by glob pattern(s):
    ```sh
    ./bin/redactyl purge pattern --glob '**/*.pem' --glob '**/*.key' --yes
    ```
  - Replace content across history using a `git filter-repo` replace-text file:
    ```sh
    ./bin/redactyl purge replace --replacements replacements.txt --yes
    ```
  - Add `--dry-run` to print the exact commands without executing, and `--summary purge.json` to write a small remediation summary JSON you can parse in CI.

### Detectors
- List available IDs:
  ```sh
  ./bin/redactyl detectors
  ```
- Enable only specific detectors:
  ```sh
  ./bin/redactyl scan --enable "twilio,github_token"
  ```
- Disable specific detectors:
  ```sh
  ./bin/redactyl scan --disable "entropy_context"
  ```
<!-- BEGIN:DETECTORS_CATEGORIES -->

Categories and example IDs (run `redactyl detectors` for the full, up-to-date list):

- Cloud & DB URIs:
  - amqp_uri_creds, aws_access_key, aws_secret_key, azure_storage_key, gcp_service_account_key, mongodb_uri_creds, mysql_uri_creds, postgres_uri_creds, redis_uri_creds, sqlserver_uri_creds
- CI/CD & developer services:
  - docker_config_auth, git_credentials_url_secret, github_token, gitlab_token, heroku_api_key, npm_token, npmrc_auth_token, rubygems_credentials, sentry_auth_token, sentry_dsn, terraform_cloud_token
- Messaging & webhooks:
  - discord_bot_token, discord_webhook, ifttt_webhook_url, slack_token, slack_webhook, telegram_bot_token, zapier_webhook_url
- Payments & email:
  - mailgun_api_key, sendgrid_api_key, stripe_secret, stripe_webhook_secret
- Google & Firebase:
  - firebase_api_key, google_api_key
- AI providers:
  - ai21_api_key, anthropic_api_key, azure_openai_api_key, cohere_api_key, groq_api_key, mistral_api_key, openai_api_key, openrouter_api_key, perplexity_api_key, replicate_api_token, stability_api_key
- AI tooling & vector DBs:
  - huggingface_token, kaggle_json_key, pinecone_api_key, qdrant_api_key, wandb_api_key, weaviate_api_key
- Other common services:
  - airtable_pat, azure_sas_token, cloudflare_token, cloudinary_url_creds, databricks_pat, datadog_api_key, datadog_app_key, digitalocean_pat, dockerhub_pat, entropy_context, flyio_access_token, hasura_admin_secret, jwt, linear_api_key, mapbox_token, netlify_build_hook, netlify_token, newrelic_api_key, notion_api_key, okta_api_token, posthog_personal_key, posthog_project_key, prisma_data_proxy_url, private_key_block, pypi_token, render_api_key, shopify_token, snyk_token, supabase_service_role_key, twilio_account_sid, twilio_api_key_secret_like, twilio_api_key_sid, twilio_auth_token, vercel_token
<!-- END:DETECTORS_CATEGORIES -->

### Output formats
- Table (default): formatted table with borders and alignment for easy reading
- Text: plain columnar output with severity, detector, location, and redacted match (use `--text`)
- JSON: machine-readable; never returns null array
- SARIF 2.1.0: for code scanning dashboards

### Public facade (for integrations)
- Stable API surface for external consumers:
  - Import `github.com/redactyl/redactyl/pkg/core`
  - Types: `core.Config`, `core.Finding`
  - Entry: `core.Scan(cfg)`

### Enterprise upload (optional)
- Upload findings JSON after a scan:
  ```sh
  redactyl scan --json --upload https://enterprise.example/api/v1/findings --upload-token $REDACTYL_TOKEN
  ```
- Envelope fields: `tool`, `version`, `schema_version`, optional `repo|commit|branch`, and `findings`.
- Schemas:
  - Findings: `docs/schemas/findings.schema.json`
  - Upload envelope: `docs/schemas/upload-envelope.schema.json`

See also: `docs/enterprise.md` for integration options.

### SARIF viewer
```sh
./bin/redactyl sarif view redactyl.sarif.json
```

### Rule reference
- See `docs/rules/README.md` for short descriptions and examples for each detector.

### CLI reference
- `./bin/redactyl --help`
- `./bin/redactyl scan --help`
- `./bin/redactyl fix --help`
- `./bin/redactyl purge --help`
- `./bin/redactyl hook --help`
- `./bin/redactyl action --help`
- `./bin/redactyl update --help`
- `./bin/redactyl completion --help`

### Common scan flags
- **--path, -p**: path to scan (default: .)
- **--staged**: scan staged changes
- **--history N**: scan last N commits
- **--base BRANCH**: scan diff vs base branch
- **--include / --exclude**: comma-separated globs
  - Globs use doublestar-style matching with forward slashes, e.g., `**/*.go`, `src/**/test_*.ts`. On Windows, use `/` in patterns.
- **--max-bytes**: skip files larger than this (default: 1 MiB)
- **--threads**: worker count (default: GOMAXPROCS)
- **--enable / --disable**: comma-separated detector IDs
- **--json / --sarif / --text**: select output format (table is default)
- **--fail-on**: low | medium | high (default: medium)
- **--guide**: print suggested remediation commands after a scan
 - **--no-upload-metadata**: when used with `--upload`, omit repo/commit/branch from the envelope (privacy-sensitive CI)

### Exit codes
- 0: no findings or below threshold
- 1: findings at or above threshold (see `--fail-on`)
- 2: error while scanning

### CI usage (GitHub Actions)
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

### Pre-commit hook
```sh
./bin/redactyl hook install --pre-commit
```
Or add via the pre-commit framework:

```yaml
- repo: https://github.com/redactyl/redactyl
  rev: v0.1.0
  hooks:
    - id: redactyl-scan
```

### GitHub Action template
```sh
./bin/redactyl action init
```

### Notes
- Redactyl respects `.redactylignore` for path filtering.
- Findings are deduplicated by `(path|detector|match)`.
- Baseline suppresses previously seen findings; update your baseline after intentionally introduced secrets are handled (for example, false positives).

### Version
```sh
./bin/redactyl version
```

### Updates & Changelog
- Check for a newer version is displayed on scan (can be disabled via flags/config).
- Update in-place from GitHub Releases:
  ```sh
  ./bin/redactyl update
  ```
 - See `CHANGELOG.md` for notable changes.

### Compatibility
- Versioning policy (SemVer):
  - CLI: additive flags and outputs are minor; breaking changes bump major.
  - JSON output: backwards-compatible field additions are minor; removing/renaming fields is major.
  - SARIF: remains compliant with v2.1.0; we only add optional fields (e.g., helpUri) without breaking consumers.
  - Rule IDs: stable; renames or removals are major. New rule IDs may be added in any minor.
  - Public Go API (`pkg/core`): follows SemVer; breaking changes require a major version.

### License
- Apache-2.0. See [`LICENSE`](LICENSE).

### Contributing
- See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- For new detectors, please include tests with your PR (positive and negative cases). See `internal/detectors/README.md` for a short guide and template.

### Enterprise
- Commercial offerings (dashboard, org policies, PR gating, SSO, hosted option) are available.
- Options:
  - Upload from OSS CLI to your server: `--json --upload` (see schemas in `docs/schemas/`).
  - Or run scans in Enterprise workers via `github.com/redactyl/redactyl/pkg/core`.
- Inquiries: open a GitHub Discussion (Q&A) titled "Enterprise inquiry".
