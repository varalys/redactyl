# Redactyl Integration Tests

**Purpose:** Real-world validation tests using actual artifacts to verify end-to-end functionality.

## Quick Demo 🎬

Want to see Redactyl in action? Run the demo:

```bash
./test/integration/demo.sh
```

Shows Helm charts, Kubernetes manifests, and archive scanning in under 2 minutes. Perfect for presentations!

**[Read the Demo Guide →](DEMO.md)**

---

## Philosophy

Go unit tests are great for testing individual components, but they can miss critical integration issues:
- Real Gitleaks binary behavior vs mocked responses
- Actual artifact formats (OCI manifests, Helm charts) vs synthetic test data
- Performance characteristics with large files
- Edge cases in real-world artifacts

This integration test suite downloads or generates real artifacts and verifies Redactyl scans them correctly.

**Key Testing Principle:** Redactyl works out-of-the-box with zero configuration - just run `redactyl scan` to detect secrets in regular files. Artifact flags (`--helm`, `--k8s`, `--archives`, `--containers`) enable specialized scanning for those types.

## Test Categories

1. **Baseline Tests** - Known secrets in simple files (fast, always run)
2. **Archive Tests** - Real zip/tar/tgz files with secrets (fast)
3. **Container Tests** - Docker images with embedded secrets (medium)
4. **Helm Tests** - Real Helm charts from repositories (medium)
5. **K8s Tests** - Kubernetes manifests from real deployments (fast)
6. **Performance Tests** - Large artifacts to verify streaming/limits (slow)

## Directory Structure

```
test/integration/
├── README.md                 # This file
├── run-tests.sh             # Main test runner
├── fixtures/                # Pre-seeded test artifacts
│   ├── secrets/             # Known secrets in various formats
│   ├── archives/            # Test archives
│   ├── containers/          # Small container images
│   ├── helm/                # Helm charts
│   └── k8s/                 # K8s manifests
├── downloads/               # Downloaded artifacts (gitignored)
├── scripts/                 # Helper scripts
│   ├── download-artifacts.sh
│   ├── generate-fixtures.sh
│   └── verify-results.sh
└── results/                 # Test outputs (gitignored)
```

## Running Tests

```bash
# Run all integration tests
./test/integration/run-tests.sh

# Run specific test category
./test/integration/run-tests.sh baseline
./test/integration/run-tests.sh containers

# Run with verbose output
VERBOSE=1 ./test/integration/run-tests.sh

# Skip downloads (use cached artifacts)
SKIP_DOWNLOAD=1 ./test/integration/run-tests.sh
```

## Test Expectations

Each test defines:
1. **Input:** Artifact to scan
2. **Expected findings:** Minimum number of secrets, specific detector IDs, file paths
3. **Performance:** Maximum scan time, memory usage
4. **Exit code:** Success/failure based on --fail-on threshold

Tests fail if:
- Expected secrets are NOT found (false negatives)
- Scan crashes or hangs
- Performance exceeds acceptable limits
- Virtual paths are malformed

## Adding New Tests

1. Add fixture to `fixtures/` or download URL to `scripts/download-artifacts.sh`
2. Add test case to `run-tests.sh` with expectations
3. Run test and verify output
4. Document in this README

## CI Integration

These tests run in GitHub Actions on:
- Every PR (baseline + fast tests only)
- Every merge to main (all tests)
- Nightly (all tests + performance benchmarks)

## Maintenance

- **Monthly:** Update download URLs if upstream artifacts change
- **Quarterly:** Add new real-world test cases from user reports
- **After each release:** Verify all tests pass with new binary
