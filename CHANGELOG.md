# Changelog

## Unreleased
- Add `redactyl ci init --provider {gitlab|bitbucket|azure}` to generate CI templates for GitLab, Bitbucket Pipelines, and Azure DevOps.
- README: document new CI usage commands.
- Detection: add validator heuristics and structured context foundation
  - New `internal/validate` and `internal/ctxparse`
  - Validators wired across major detectors; `--no-validators` flag to disable
  - Expanded tests for validators and coverage check

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project adheres to Semantic Versioning.

## Unreleased
### Added
- Public facade `pkg/core` exposing `Config`, `Finding`, and `Scan(cfg)`.
- CLI `--upload` and `--upload-token` to POST findings JSON (envelope includes `schema_version: "1"`).
- JSON Schemas for findings and upload envelope under `docs/schemas/`.
- README and CONTRIBUTING updates documenting integration paths and contributor guidelines.
