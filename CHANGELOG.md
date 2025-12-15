# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project adheres to Semantic Versioning.

## v1.0.0 - 2025-12-15

### Added
- Deep artifact scanning (archives, containers, IaC hotspots)
  - Flags: `--archives`, `--containers`, `--iac`
  - Guardrails: `--max-archive-bytes`, `--max-entries`, `--max-depth`, `--scan-time-budget`
  - New optional global guardrail: `--global-artifact-budget` (config: `global_artifact_budget`) to cap total deep-scan time across all artifacts
  - IaC hotspots: Terraform state (`*.tfstate`) selective JSON extraction; Kubeconfig selective YAML extraction
  - Virtual paths for entries inside artifacts (e.g., `archive.zip::path/file.txt`, `image.tar::<layerID>/path`)
  - Bounded worker pool for artifact processing (driven by `threads` → `limits.Workers`)
  - Streaming readers; no extraction to disk; binary/MIME skips
- Output improvements
  - New `--json-extended` format adds `artifactStats` alongside `findings` and includes `schema_version: "1"`
  - SARIF: `run.properties.artifactStats` populated when available
  - CLI footer displays artifact abort counters when non‑zero (bytes/entries/depth/time)
- Filtering
  - Artifact filenames now respect include/exclude globs (in addition to `.redactylignore`)
- Docs & tooling
  - README: deep scanning section with comprehensive artifact scanning documentation
  - CI templates command: `redactyl ci init --provider {gitlab|bitbucket|azure}`
  - Public facade `pkg/core` exposing `Config`, `Finding`, and `Scan(cfg)`
  - JSON Schemas for findings and upload envelope under `docs/schemas/`

### Changed
- Engine integrates artifact scanning after normal phases; results incorporate virtual paths and optional `artifactStats`
- Default JSON output remains unchanged; extended fields gated behind `--json-extended`
- README/CONTRIBUTING updated with new usage and contributor guidance

### Fixed
- Lint and docs workflow stability (errcheck/gocritic tidy ups)
- **Silent failures during deep artifact scanning are now reported in `Result.ArtifactErrors`.**
