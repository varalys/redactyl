# Contributing to Redactyl

Thank you for your interest in contributing!

- Use Go 1.25+.
- Run tests locally: `go test ./... -race`.
- Lint: `golangci-lint run` (CI will run it too; see `.golangci.yml`).
- Add tests for new detectors and features.
- Keep PRs focused and small; include a brief description.

## Development

- Build: `make build` (outputs `bin/redactyl`).
- Run: `./bin/redactyl --help`.
- Generate config: `./bin/redactyl config init`.
- E2E CLI tests: see `cmd/redactyl/e2e_cli_test.go` for examples of validating JSON/SARIF shapes.

### Architecture Overview

Redactyl is a **deep artifact scanner** that combines intelligent artifact parsing with Gitleaks-powered secret detection:

**Key Components:**
- `internal/artifacts/` - Artifact parsing (OCI images, Helm charts, K8s manifests, archives)
- `internal/scanner/` - Scanner abstraction and Gitleaks integration
- `internal/engine/` - Scan orchestration and result aggregation
- `internal/config/` - Configuration management (CLI + file-based)
- `pkg/core/` - Public API surface for external integrations

**How It Works:**
1. Parse complex artifacts (containers, Helm, K8s, nested archives)
2. Stream file contents without disk extraction
3. Track virtual paths through nested structures (e.g., `chart.tgz::templates/secret.yaml`)
4. Scan content with Gitleaks detection engine
5. Enrich findings with artifact metadata and context

See `docs/gitleaks-integration.md` for detailed integration architecture.

## Code of Conduct

Please follow the Code of Conduct in `CODE_OF_CONDUCT.md`.

## Release

- Bump version via tag `vX.Y.Z`.
- CI (GoReleaser) publishes archives and deb/rpm/apk.

## Public API stability (`pkg/core`)

- The public facade `pkg/core` is the stable import surface for external integrations.
- Exposed types and functions today:
  - `core.Config`, `core.Finding`, `core.Scan(cfg)`
- Semver policy:
  - Backwards-compatible changes (adding optional fields, new functions) are minor releases.
  - Breaking changes to `pkg/core` require a major version bump.
  - Prefer additive changes; if you need context, add `core.ScanContext(ctx, cfg)` rather than breaking `Scan`.

## JSON schemas and upload envelope

- Schemas live in `docs/schemas/`:
  - `findings.schema.json` describes the JSON emitted by `--json`.
  - `upload-envelope.schema.json` describes the POST body when using `--upload`.
- `schema_version` policy (upload envelope):
  - Backwards-compatible shape changes keep the same version.
  - Breaking changes increment `schema_version` (as a string). Bump the const in code and update the schema.
  - Prefer servers to accept multiple known versions during transitions.
- Please include/adjust contract tests when changing JSON output.

## Detection Rules

Redactyl uses [Gitleaks](https://github.com/gitleaks/gitleaks) exclusively for all secret detection. We focus on **artifact intelligence** while Gitleaks handles **pattern matching**.

### Adding New Detection Patterns

**Option 1: Contribute to Gitleaks (Recommended)**
- Benefits everyone in the ecosystem
- Maintained by Gitleaks team
- Automatically available in Redactyl
- Submit PR: https://github.com/gitleaks/gitleaks

**Option 2: Custom Local Rules**
Create a `.gitleaks.toml` config file:

```toml
[extend]
useDefault = true

[[rules]]
id = "custom-api-key"
description = "Custom API Key Pattern"
regex = '''custom_key_[a-zA-Z0-9]{32}'''
entropy = 4.0
```

Test with: `redactyl scan --gitleaks-config .gitleaks.toml`

### Working on Scanner Integration

If you're improving the Gitleaks integration itself:

1. **Read the architecture docs:** `docs/gitleaks-integration.md`
2. **Key files:**
   - `internal/scanner/scanner.go` - Scanner interface
   - `internal/scanner/gitleaks/scanner.go` - Gitleaks implementation
   - `internal/scanner/gitleaks/binary.go` - Binary management
3. **Test thoroughly:**
   - Unit tests: `go test ./internal/scanner/gitleaks/...`
   - Integration tests: `./test/integration/run-tests.sh baseline`
4. **Consider:**
   - Virtual path preservation
   - Temp file cleanup
   - Error handling and messages
   - Cross-platform compatibility (Windows, macOS, Linux)

## Tooling

- Formatting and linting:
  - Use `go fmt`, `go vet`, and `golangci-lint run` (CI enforces).
  - A `make lint` target is recommended (use if available).
- Modules:
  - Run `go mod tidy` before submitting.
  - Go workspaces are supported for local multi-repo development.

## Testing and benchmarks

### Unit Tests
- Run all tests: `go test ./...`
- Run specific package: `go test ./internal/artifacts/...`
- With race detector: `go test ./... -race`
- Coverage: `go test ./... -coverprofile=coverage.out`

### Integration Tests
Redactyl has end-to-end integration tests that validate real artifact scanning with Gitleaks:

```bash
# Run all integration tests
./test/integration/run-tests.sh

# Run specific test category
./test/integration/run-tests.sh baseline
./test/integration/run-tests.sh helm
./test/integration/run-tests.sh k8s

# Skip download (if Gitleaks already available)
SKIP_DOWNLOAD=1 ./test/integration/run-tests.sh
```

See `test/integration/TESTING_GUIDE.md` for detailed information.

### Benchmarks
- Run benchmarks: `go test -bench=. -benchmem ./...`
- Specific package: `go test -bench=. ./internal/artifacts/`
- If you add performance-sensitive code (artifact parsing, scanning), include benchmarks

## Process and governance

- Keep PRs small and focused; include a brief rationale and screenshots/output where relevant.
- Link issues if applicable; draft PRs welcome for early feedback.
- No CLA required at this time. Sign-offs are optional unless otherwise requested.
- Conventional commits are welcome but not required.

## Security

- Please do not file public issues for suspected vulnerabilities.
- Report privately via GitHub Security Advisories for this repo, or contact the maintainer via the profile email.
- We will acknowledge receipt within a reasonable time and coordinate a fix and disclosure.
