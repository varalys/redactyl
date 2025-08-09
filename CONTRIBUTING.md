# Contributing to Redactyl

Thank you for your interest in contributing!

- Use Go 1.23+.
- Run tests locally: `go test ./...`.
- Lint: `golangci-lint run` (CI will run it too).
- Add tests for new detectors and features.
- Keep PRs focused and small; include a brief description.

## Development

- Build: `make build` (outputs `bin/redactyl`).
- Run: `./bin/redactyl --help`.
- Generate config: `./bin/redactyl config init`.

## Code of Conduct

Please follow the Code of Conduct in `CODE_OF_CONDUCT.md`.

## Release

- Bump version via tag `vX.Y.Z`.
- CI (GoReleaser) publishes archives and deb/rpm/apk.


