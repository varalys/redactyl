# Redactyl Enterprise Integration

This document outlines two integration options for organizations.

## Option A: Upload JSON from OSS CLI (loosely coupled)

- Run scans in CI/dev and upload findings to your server:
  ```sh
  redactyl scan --json --upload https://your.example/api/v1/findings \
    --upload-token $REDACTYL_TOKEN
  ```
- Envelope fields: `tool`, `version`, `schema_version`, optional `repo|commit|branch`, and `findings`.
- Schemas:
  - Findings: `docs/schemas/findings.schema.json`
  - Upload envelope: `docs/schemas/upload-envelope.schema.json`

## Option B: Run scans in Enterprise workers (tighter integration)

- Import the stable facade:
  ```go
  import "github.com/franzer/redactyl/pkg/core"
  ```
- Use `core.Config`, `core.Finding`, and `core.Scan(cfg)`.
- Go workspaces make local multi-repo development easy:
  ```sh
  mkdir work && cd work
  git clone git@github.com:redactyl/redactyl.git
  git clone git@github.com:redactyl/redactyl-enterprise.git
  go work init
  go work use ./redactyl ./redactyl-enterprise
  ```

## Versioning & Stability

- `pkg/core` follows semver and is intentionally small and stable.
- The upload envelope includes a `schema_version` for compatibility across upgrades.

For inquiries, see the Enterprise section of the README.
