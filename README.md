## Redactyl

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

### Quick start
- Default scan:
  ```sh
  ./bin/redactyl scan
  ```
- With guidance (suggested remediation commands):
  ```sh
  ./bin/redactyl scan --guide
  ```
- JSON:
  ```sh
  ./bin/redactyl scan --json
  ```
- SARIF:
  ```sh
  ./bin/redactyl scan --sarif > redactyl.sarif.json
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

### Remediation
- Forward-only fixes (safe defaults):
  - Remove a tracked file and ignore it:
    ```sh
    ./bin/redactyl fix path .env --add-ignore
    ```
  - Redact secrets in-place using regex and commit:
    ```sh
    ./bin/redactyl fix redact --file app.yaml --pattern 'password:\s*\S+' --replace 'password: <redacted>'
    ```
  - Generate/update `.env.example` from `.env` and ensure `.env` is ignored:
    ```sh
    ./bin/redactyl fix dotenv --from .env --to .env.example --add-ignore
    ```
- History rewrite (dangerous; creates a backup branch; you likely must force-push):
  - Remove a single path from all history:
    ```sh
    ./bin/redactyl purge path secrets.json --yes --backup-branch my-backup
    ```
  - Remove by glob pattern(s):
    ```sh
    ./bin/redactyl purge pattern --glob '**/*.pem' --glob '**/*.key' --yes
    ```
  - Replace content across history using a `git filter-repo` replace-text file:
    ```sh
    ./bin/redactyl purge replace --replacements replacements.txt --yes
    ```
  - Add `--dry-run` to print the exact commands without executing, and `--summary purge.json` to write a remediation summary.

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
- Current detector IDs:
  - aws_access_key
  - aws_secret_key
  - github_token
  - slack_token
  - jwt
  - private_key_block
  - entropy_context
  - stripe_secret
  - twilio_account_sid
  - twilio_api_key_sid
  - twilio_auth_token
  - twilio_api_key_secret_like

### Output formats
- Table (default): human-friendly summary
- JSON: machine-readable; never returns null array
- SARIF 2.1.0: for code scanning dashboards

### SARIF viewer
```sh
./bin/redactyl sarif view redactyl.sarif.json
```

### CLI reference
- `./bin/redactyl --help`
- `./bin/redactyl scan --help`
- `./bin/redactyl fix --help`
- `./bin/redactyl purge --help`
- `./bin/redactyl hook --help`
- `./bin/redactyl action --help`
- `./bin/redactyl update --help`

### Common scan flags
- **--path, -p**: path to scan (default: .)
- **--staged**: scan staged changes
- **--history N**: scan last N commits
- **--base BRANCH**: scan diff vs base branch
- **--include / --exclude**: comma-separated globs
- **--max-bytes**: skip files larger than this (default: 1 MiB)
- **--threads**: worker count (default: GOMAXPROCS)
- **--enable / --disable**: comma-separated detector IDs
- **--json / --sarif**: select output format
- **--fail-on**: low | medium | high (default: medium)
- **--guide**: print suggested remediation commands after a scan

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
```

### Pre-commit hook
```sh
./bin/redactyl hook install --pre-commit
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

### Updates
- Check for a newer version is displayed on scan (can be disabled via flags/config).
- Update in-place from GitHub Releases:
  ```sh
  ./bin/redactyl update
  ```

License, contribution guidelines, and detailed examples can be added here if needed.

---

Badges

![Tests](https://github.com/redactyl/redactyl/actions/workflows/test.yml/badge.svg)
![Release](https://github.com/redactyl/redactyl/actions/workflows/release.yml/badge.svg)