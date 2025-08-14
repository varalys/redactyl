# Contributing to Redactyl

Thank you for your interest in contributing!

- Use Go 1.23+.
- Run tests locally: `go test ./... -race`.
- Lint: `golangci-lint run` (CI will run it too; see `.golangci.yml`).
- Add tests for new detectors and features.
- Keep PRs focused and small; include a brief description.

## Development

- Build: `make build` (outputs `bin/redactyl`).
- Run: `./bin/redactyl --help`.
- Generate config: `./bin/redactyl config init`.
 - E2E CLI tests: see `cmd/redactyl/e2e_cli_test.go` for examples of validating JSON/SARIF shapes.

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

## Detector guidelines

- Quality:
  - Keep false positives low. Prefer precise regexes or contextual checks.
  - Map severity to risk realistically; use `low|medium|high` consistently.
  - Provide a sensible `confidence` in [0,1]. Aim for >0.9 when highly certain.
  - Use validator heuristics (prefix/length/alphabet, simple decoders) to raise confidence and filter near-misses. See `internal/validate`.
- Performance:
  - Avoid quadratic scans; use compiled regexes and short-circuit early.
  - Respect size limits and binary detection already enforced by the engine.
  - Structured context: prefer lightweight JSON/YAML passes (`internal/ctxparse`) when key/value positions matter; guard by file extension and size.
- IDs and docs:
  - Add a unique, stable ID in `internal/detectors` and update the README list if user-facing.
  - Document any non-trivial validator criteria in `docs/rules/README.md` under your rule ID.
- Tests:
  - Add positive and negative cases; cover edge cases.
  - Consider fuzz tests where input surface is large.
  - When adding validators, include tests that assert both acceptance (true positive) and rejection (near-miss) cases. For end-to-end validator effects, prefer invoking `detectors.RunAll`.
  - When adding structured scanning, include at least one test where a value is split across lines (YAML `|`) or nested in JSON, and verify `RunAll` catches it.

## Tooling

- Formatting and linting:
  - Use `go fmt`, `go vet`, and `golangci-lint run` (CI enforces).
  - A `make lint` target is recommended (use if available).
- Modules:
  - Run `go mod tidy` before submitting.
  - Go workspaces are supported for local multi-repo development.

## Testing and benchmarks

- Run all tests: `go test ./...`
- Benchmarks (optional): `go test -bench=. -benchmem ./...`
- If you add performance-sensitive code (e.g., detectors), consider including a basic benchmark.

## Process and governance

- Keep PRs small and focused; include a brief rationale and screenshots/output where relevant.
- Link issues if applicable; draft PRs welcome for early feedback.
- No CLA required at this time. Sign-offs are optional unless otherwise requested.
- Conventional commits are welcome but not required.

## Security

- Please do not file public issues for suspected vulnerabilities.
- Report privately via GitHub Security Advisories for this repo, or contact the maintainer via the profile email.
- We will acknowledge receipt within a reasonable time and coordinate a fix and disclosure.
