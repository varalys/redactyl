## Deep scanning guide

This document explains how Redactyl scans archives, containers, Helm charts, Kubernetes manifests, and IaC hotspots without extracting to disk, how virtual paths work, the guardrails available, and performance tuning tips.

**Last Updated:** 2025-12-15

### Overview

- **Archives:** `.zip`, `.tar`, `.tgz`, `.tar.gz`, `.gz` are scanned by streaming entries and emitting only text-like content. Nested archives are supported up to a configurable depth.
- **Containers:** Tarballs produced by `docker save` (detected via `manifest.json` or `<layerID>/layer.tar`) are scanned. Supports both Docker and OCI image formats. Entries inside layer tarballs are represented using a virtual path: `image.tar::<layerID>/path/in/layer`.
- **Registry Images:** Remote OCI images are scanned by streaming layers directly from the registry API. Virtual paths include the image reference and layer digest: `gcr.io/proj/img:tag::sha256:digest/path/in/layer`.
- **Helm Charts:** Both packaged Helm charts (`.tgz` archives) and unpacked chart directories are scanned. Redactyl parses `Chart.yaml`, `values.yaml`, and all `templates/` files. Virtual paths show chart structure: `my-chart.tgz::templates/secret.yaml`.
- **Kubernetes Manifests:** YAML files containing Kubernetes resources are auto-detected by structure and naming. Supports multi-document YAML files. Scans Secret objects, ConfigMaps, and container environment variables in Pods/Deployments.
- **IaC hotspots:** Terraform state files (`*.tfstate`) and kubeconfigs are scanned with selective extraction of likely secret values when files are small; large files fall back to bounded text emission.
- **Virtual paths:** Entries emitted from inside artifacts use `::` to show origin chains, e.g. `outer.zip::inner.tgz::path/file.txt`.

### Guardrails

Per‑artifact guardrails apply to each archive/container individually:

- `--max-archive-bytes` / `max_archive_bytes`: limit total decompressed bytes processed per artifact.
- `--max-entries` / `max_entries`: limit number of emitted entries per artifact.
- `--max-depth` / `max_depth`: limit nested archive recursion depth.
- `--scan-time-budget` / `scan_time_budget`: time budget per artifact.

Global guardrail (optional):

- `--global-artifact-budget` / `global_artifact_budget`: caps total time spent across all artifacts in a scan.

When limits are exceeded, deep scanning for the current artifact (or for all artifacts in the case of the global budget) aborts early. Counters are recorded for bytes/entries/depth/time aborts and exposed in outputs.

### Performance tuning

- `--threads` controls worker parallelism for artifact scanning. Defaults to the number of CPUs when `0` in config. Increase if you have many independent archives and sufficient IO/CPU; decrease if you notice contention.
- Keep `max-archive-bytes` and `scan-time-budget` conservative to avoid spending time on very large or deeply nested archives.
- Use include/exclude globs to narrow which artifact filenames are processed. For example: `--include "**/releases/**" --exclude "**/node_modules/**"`.

### Examples

**Basic Scanning:**

```sh
# Scan all archives with default guardrails
redactyl scan --archives

# Scan containers with larger byte budget and small per‑artifact time budget
redactyl scan --containers --max-archive-bytes 67108864 --scan-time-budget 5s

# Scan Helm charts (both .tgz and directories)
redactyl scan --helm

# Scan Kubernetes manifests
redactyl scan --k8s

# Scan remote registry image
redactyl scan --registry gcr.io/my-project/image:latest
```

**Combined Scanning:**

```sh
# Scan containers, Helm charts, and K8s manifests together (cloud-native stack)
redactyl scan --containers --helm --k8s

# Scan everything with guardrails
redactyl scan --archives --containers --helm --k8s --iac --global-artifact-budget 60s
```

**Advanced Usage:**

```sh
# Apply a global budget across all artifacts and restrict artifact filenames via globs
redactyl scan --archives --include "**/allowed*" --exclude "**/blocked*" --global-artifact-budget 10s

# Scan specific Helm chart with custom config
redactyl scan --helm -p ./my-chart --json

# Scan Kubernetes deployments directory
redactyl scan --k8s -p ./k8s-manifests/
```

### Output

- Default JSON (`--json`) is a stable array of findings.
- Extended JSON (`--json --json-extended`) returns an object with `schema_version`, `findings`, and `artifact_stats` counters `{bytes, entries, depth, time}`.
- SARIF (`--sarif`) includes counters in `runs[0].properties.artifactStats`.


