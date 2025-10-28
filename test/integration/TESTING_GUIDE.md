# Integration Testing Guide

## Why Integration Tests?

Go unit tests are excellent for testing individual components, but they can miss:

1. **Real binary behavior** - Mocking Gitleaks output vs actual Gitleaks binary
2. **Format edge cases** - Real OCI manifests, Helm charts, K8s YAML complexity
3. **Performance characteristics** - Streaming large artifacts, memory usage
4. **End-to-end workflows** - CLI flags → engine → scanner → output
5. **Regression detection** - Real-world scenarios that broke in production

This integration test suite uses **real artifacts** and **real commands** to verify the entire system works as users expect.

## Quick Start

```bash
# 1. Generate test fixtures (fake secrets for testing)
./test/integration/scripts/generate-fixtures.sh

# 2. Run all tests
./test/integration/run-tests.sh

# 3. Run specific category
./test/integration/run-tests.sh helm

# 4. Verbose output
VERBOSE=1 ./test/integration/run-tests.sh

# 5. Skip downloads (use cached artifacts)
SKIP_DOWNLOAD=1 ./test/integration/run-tests.sh
```

**Note:** Redactyl works out-of-the-box without any flags - just run `redactyl scan` to scan regular files for secrets. Artifact flags (`--helm`, `--k8s`, `--archives`, `--containers`) enable additional specialized scanning for those artifact types.

## Test Categories

### Baseline Tests (Fast, ~5s)
Basic secret detection in simple files. Always run these first.

```bash
./test/integration/run-tests.sh baseline
```

**What it tests:**
- Single secret in text file
- Multiple secrets in one file
- Secrets in JSON/YAML
- Gitleaks binary integration

**Expected output:**
```
=== Baseline Tests ===
► Test: baseline-simple-secret
  ✓ PASS
  ✓ Found 2 findings
► Test: baseline-multiple-secrets
  ✓ PASS
  ✓ Found 3 findings
...
```

### Archive Tests (Fast, ~10s)
Streaming archives without disk extraction.

```bash
./test/integration/run-tests.sh archives
```

**What it tests:**
- Zip files with secrets
- Tar.gz with secrets
- Nested archives (zip inside tar)
- Virtual path preservation (`file.zip::inner.txt`)

**Expected virtual paths:**
```json
{
  "path": "secrets.zip::credentials.txt",
  "line": 3,
  "match": "api_token=..."
}
```

### Container Tests (Medium, ~30s)
Docker image scanning with OCI format support.

```bash
./test/integration/run-tests.sh containers
```

**What it tests:**
- Docker save format
- OCI image format
- Layer scanning
- Virtual paths with layer IDs

**Note:** Downloads Alpine Linux image (~3MB) on first run.

### Helm Tests (Fast, ~10s)
Helm chart scanning for values and templates.

```bash
./test/integration/run-tests.sh helm
```

**What it tests:**
- Helm chart directories
- Packaged charts (.tgz)
- Secrets in values.yaml
- Secrets in templates/

**Expected findings:**
- Chart values: `test-chart::values.yaml`
- Templates: `test-chart::templates/secret.yaml`

### Kubernetes Tests (Fast, ~5s)
K8s manifest detection and scanning.

```bash
./test/integration/run-tests.sh k8s
```

**What it tests:**
- Secret manifests
- Deployment env vars
- Multi-document YAML
- ConfigMaps with secrets

### Performance Tests (Slow, ~60s)
Large artifacts and time budget enforcement.

```bash
./test/integration/run-tests.sh performance
```

**What it tests:**
- Large archives (1000+ files)
- Time budget enforcement
- Memory usage (no leaks)
- Graceful timeout handling

**Note:** Creates ~10MB test archive on first run.

### Combined Tests
All artifact types scanned together.

```bash
./test/integration/run-tests.sh combined
```

## Understanding Test Output

### Success
```
► Test: helm-chart-directory
  ✓ PASS
  ✓ Found 3 findings
```

### Failure
```
► Test: helm-chart-directory
  ✗ FAIL (exit code: 1)
  ✗ Expected at least 1 findings, got 0
```

### Skip
```
► Test: container-oci-format
  ⊘ SKIP: Alpine image not downloaded
```

### Verbose Mode
```bash
VERBOSE=1 ./test/integration/run-tests.sh baseline
```

Shows:
- Full command executed
- Complete JSON output
- Error messages
- Timing information

## Debugging Failed Tests

### Step 1: Run test in verbose mode
```bash
VERBOSE=1 ./test/integration/run-tests.sh baseline
```

### Step 2: Check test results
```bash
cat test/integration/results/baseline-simple-secret.json
```

### Step 3: Reproduce manually
```bash
./bin/redactyl scan --json test/integration/fixtures/secrets/simple.txt
```

### Step 4: Verify fixtures
```bash
# Check fixture content
cat test/integration/fixtures/secrets/simple.txt

# Regenerate if needed
./test/integration/scripts/generate-fixtures.sh
```

### Step 5: Test with Gitleaks directly
```bash
gitleaks detect --no-git --source test/integration/fixtures/secrets/simple.txt
```

## Adding New Tests

### 1. Create or download test artifact

**Option A: Add to fixtures**
```bash
# Edit generate-fixtures.sh
vim test/integration/scripts/generate-fixtures.sh

# Add new fixture generation
cat > "$FIXTURES_DIR/mytest/secret.yaml" << 'EOF'
apiKey: sk_test_1234567890abcdefghijklmnopqrst
EOF
```

**Option B: Download real artifact**
```bash
# Edit download-artifacts.sh
vim test/integration/scripts/download-artifacts.sh

# Add download command
curl -sL https://example.com/artifact.tar.gz \
    -o "$DOWNLOADS_DIR/artifact.tar.gz"
```

### 2. Add test case to run-tests.sh

```bash
vim test/integration/run-tests.sh

# Add to appropriate test suite function
test_mytest() {
    echo -e "\n${YELLOW}=== My Test Suite ===${NC}"

    run_test "mytest-case-1" "mytest" \
        "$REDACTYL_BIN" scan --json --helm "$FIXTURES_DIR/mytest/chart"
    verify_findings "$RESULTS_DIR/mytest-case-1.json" 2 "expected-path"
}
```

### 3. Run and verify

```bash
./test/integration/run-tests.sh mytest
```

### 4. Document expectations

Add to this guide:
- What the test validates
- Expected findings
- How to reproduce manually

## CI Integration

Tests run automatically in GitHub Actions:

### On Pull Requests
- Fast suite only (baseline, archives, helm, k8s)
- ~2 minutes total
- Blocks merge if failing

### On Push to Main
- Full suite including containers
- ~5 minutes total

### Nightly
- Full suite + performance benchmarks
- ~60 minutes total
- Results uploaded as artifacts

### Manual Trigger
```bash
# Via GitHub UI: Actions → Integration Tests → Run workflow
# Select test category or leave empty for all
```

## Test Fixtures vs Downloads

### Fixtures (Checked into Git)
- Small files with fake secrets
- Generated by `generate-fixtures.sh`
- Version controlled
- Fast to create

**Use for:** Baseline tests, unit-like integration tests

### Downloads (Gitignored)
- Real artifacts from internet
- Large files (Docker images, Helm charts)
- Cached locally
- Downloaded on first run

**Use for:** Real-world validation, performance tests

## Best Practices

### ✅ DO

- Run baseline tests before committing
- Add test for every bug fix
- Use real artifacts for edge cases
- Document expected findings
- Keep tests fast (<1 minute per category)

### ❌ DON'T

- Check large artifacts into git
- Use real secrets (even expired ones)
- Skip tests because they're slow
- Mock Gitleaks output (use real binary)
- Ignore performance regressions

## Troubleshooting

### "Gitleaks not found in PATH"

```bash
# macOS
brew install gitleaks

# Linux
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz
tar -xzf gitleaks_8.18.0_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/
```

### "Binary not found"

```bash
# Build Redactyl first
make build

# Or specify path
REDACTYL_BIN=/path/to/redactyl ./test/integration/run-tests.sh
```

### "No findings detected"

Possible causes:
1. Gitleaks rules don't match test secrets
2. Fixtures not generated
3. File format issues

```bash
# Regenerate fixtures
./test/integration/scripts/generate-fixtures.sh

# Test with Gitleaks directly
gitleaks detect --no-git --source test/integration/fixtures/secrets/simple.txt

# Check Gitleaks version
gitleaks version
```

### "Tests taking too long"

```bash
# Run fast tests only
./test/integration/run-tests.sh baseline

# Skip downloads
SKIP_DOWNLOAD=1 ./test/integration/run-tests.sh

# Run specific test
./test/integration/run-tests.sh helm
```

### "Docker not available"

Container tests will be skipped automatically. To run them:

```bash
# Install Docker
# macOS: Docker Desktop
# Linux: docker.io package

# Then re-run
./test/integration/run-tests.sh containers
```

## Performance Benchmarking

### Measure scan time

```bash
time ./bin/redactyl scan --archives test/integration/downloads/large-archive.tar.gz
```

### Memory profiling

```bash
/usr/bin/time -v ./bin/redactyl scan --containers test/integration/downloads/alpine.tar
```

### Continuous benchmarking

Nightly runs track performance over time:
- Scan time per artifact type
- Memory usage
- Findings count (regression detection)

Results: Actions → Performance Benchmarks → Artifacts

## Examples

### Add test for new detector

```bash
# 1. Create fixture with secret
cat > test/integration/fixtures/secrets/sendgrid.txt << 'EOF'
SENDGRID_API_KEY=SG.1234567890abcdefghijklmnopqrstuvwxyz
EOF

# 2. Run manually to verify
./bin/redactyl scan --json test/integration/fixtures/secrets/sendgrid.txt

# 3. Add to baseline tests
# Edit run-tests.sh, add test case
```

### Test new Helm chart

```bash
# 1. Download chart
helm pull bitnami/postgresql --destination test/integration/downloads/

# 2. Run scan
./bin/redactyl scan --json --helm test/integration/downloads/postgresql-*.tgz

# 3. Add test case if findings expected
```

### Reproduce user bug report

```bash
# User reports: "Scan hangs on large tar.gz"

# 1. Get artifact URL from bug report
wget https://example.com/problematic.tar.gz -P test/integration/downloads/

# 2. Reproduce
./bin/redactyl scan --archives test/integration/downloads/problematic.tar.gz

# 3. Add regression test
# Edit run-tests.sh with time budget
run_test "regression-large-tgz" "performance" \
    timeout 30s "$REDACTYL_BIN" scan --archives \
    --scan-time-budget 10s \
    test/integration/downloads/problematic.tar.gz
```

## Contributing

When submitting PR:

1. ✅ Run integration tests locally
2. ✅ Add test if fixing bug
3. ✅ Update this guide if adding new category
4. ✅ Check CI passes before requesting review

## Further Reading

- [Go unit tests](../../cmd/redactyl/) - Component testing
- [Gitleaks docs](https://github.com/gitleaks/gitleaks) - Detection rules
- [GitHub Actions workflow](../../.github/workflows/integration-tests.yml) - CI setup
