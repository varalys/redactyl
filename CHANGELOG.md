  # Changelog

  All notable changes to this project will be documented in this file.

  The format is based on Keep a Changelog and this project adheres to Semantic Versioning.

  ## v1.0.0 - 2025-12-16

  ### Added
  - Interactive TUI (default mode)
    - Visual findings table with color-coded severity (High/Medium/Low)
    - Detail pane with code context, metadata, and git blame info
    - Hide/show secrets toggle (`*` key) - secrets hidden by default
    - Search and filter by severity, detector, or path
    - Quick actions: open in editor (`o`), ignore (`i`), baseline (`b`), export (`e`)
    - Keyboard navigation with vim-style bindings (`j/k`, `g/G`, `Ctrl+d/u`)
    - Responsive legend adapts to terminal width
    - View cached results without rescanning (`--view-last`)
  - Cloud-native artifact scanning
    - Helm chart scanning (`--helm`) - .tgz archives and directories
    - Kubernetes manifest scanning (`--k8s`) - auto-detects K8s YAML
    - OCI image format support with layer context
    - Flags: `--archives`, `--containers`, `--iac`
    - Guardrails: `--max-archive-bytes`, `--max-entries`, `--max-depth`, `--scan-time-budget`, `--global-artifact-budget`
    - Virtual paths for nested artifacts (e.g., `chart.tgz::templates/secret.yaml`)
    - Streaming readers; no extraction to disk
  - Baseline management
    - Add/remove findings from baseline in TUI (`b`/`U`)
    - Baselined findings shown with indicator, can be filtered
  - Output formats
    - `--json-extended` adds `artifactStats` and `schema_version`
    - SARIF output with artifact stats
    - Export from TUI (JSON/CSV/SARIF)
  - Audit logging
    - All TUI actions logged to `.redactyl_audit.jsonl`
  - CI/CD support
    - `redactyl ci init --provider {gitlab|bitbucket|azure}`
    - `--no-tui` flag for non-interactive environments
    - `--fail-on` threshold for CI gates
  - Public Go API
    - `pkg/core` facade exposing `Config`, `Finding`, and `Scan(cfg)`
    - JSON schemas under `docs/schemas/`

  ### Changed
  - TUI is now the default mode (use `--no-tui` for CI/CD)
  - Secrets are hidden by default in TUI for safety

  ### Fixed
  - Silent failures during artifact scanning now reported in `Result.ArtifactErrors`
