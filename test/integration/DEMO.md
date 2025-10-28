# Redactyl Integration Demo

**Perfect for:** Product demos, conference talks, sales meetings, documentation videos

## Quick Start

```bash
./test/integration/demo.sh
```

That's it! The demo will:
1. Build Redactyl (if needed)
2. Generate test fixtures with fake secrets
3. Run 4 demo scenarios showcasing key features
4. Display beautiful formatted output with findings

## What It Demonstrates

### Demo 1: Helm Chart Scanning
Scans both packaged (.tgz) and unpacked Helm charts, finding secrets in `values.yaml` and templates.

**Output Example:**
```
┌──────────┬────────────┬────────────────────────────────────────┬──────┬───────────┐
│ SEVERITY │  DETECTOR  │                  FILE                  │ LINE │   MATCH   │
├──────────┼────────────┼────────────────────────────────────────┼──────┼───────────┤
│ high     │ github-pat │ test-chart.tgz::test-chart/values.yaml │ 11   │ ghp_…3456 │
└──────────┴────────────┴────────────────────────────────────────┴──────┴───────────┘
```

**Key Feature:** Virtual paths show nested file locations (`chart.tgz::templates/secret.yaml`)

### Demo 2: Kubernetes Manifests
Auto-detects and scans K8s Secret objects, Deployments with hardcoded env vars, ConfigMaps.

**Output Example:**
```
Findings: 2 (high: 2, medium: 0, low: 0)
Files scanned: 5
```

**Key Feature:** Multi-document YAML support, auto-detection of K8s resources

### Demo 3: Archive Scanning
Streams zip/tar/tgz files without extracting to disk, including nested archives.

**Output Example:**
```
│ high  │ github-pat  │ nested.tar::inner.zip::secret.txt │ 1  │ ghp_…abcd │
```

**Key Feature:** Virtual paths (`nested.tar::inner.zip::file`) show the full extraction path

### Demo 4: Combined Cloud-Native Stack
Scans everything together: Helm + K8s + Archives + regular files.

**Output Example:**
```
Findings: 18 (high: 18, medium: 0, low: 0)
Files scanned: 37
Scan duration: 0.95s
```

**Key Features:** Fast, comprehensive scanning of entire cloud-native deployments

## Demo Fixtures

All test data uses **fake secrets** that are safe for demos:
- GitHub Personal Access Tokens (ghp_...)
- Stripe API Keys (sk_test/sk_live...)
- Generic API keys with high entropy
- Slack webhooks
- Database passwords

**Location:** `test/integration/fixtures/`

## Customizing for Your Demo

### Add Your Own Test Data

```bash
# Edit the fixture generation script
vim test/integration/scripts/generate-fixtures.sh

# Regenerate fixtures
./test/integration/scripts/generate-fixtures.sh

# Run demo
./test/integration/demo.sh
```

### Focus on Specific Features

Edit `demo.sh` to comment out demos you don't need:

```bash
# Demo 1: Helm Chart Scanning
# ...

# Demo 2: Kubernetes Manifests
# ...

# Comment out demos 3 & 4 if showing only cloud-native features
```

### Add More Scenarios

```bash
# Add to demo.sh
echo -e "${BLUE}=== Demo 5: Container Images ===${NC}"
"$REDACTYL_BIN" scan --containers test/integration/downloads/alpine.tar
```

## Tips for Presentations

### 1. Run Once Before Presenting
```bash
./test/integration/demo.sh > /dev/null
```
This ensures everything is built and fixtures are generated.

### 2. Use Verbose Mode for Training
```bash
# Show full command output
VERBOSE=1 ./test/integration/demo.sh
```

### 3. Highlight Key Points

**When showing Helm demo:**
> "Notice the virtual path - `chart.tgz::templates/secret.yaml` - shows exactly where the secret is inside the compressed archive, without extracting to disk."

**When showing K8s demo:**
> "Redactyl auto-detected these Kubernetes manifests and found hardcoded secrets that would be deployed to your cluster."

**When showing Archive demo:**
> "This is a nested archive - a zip file inside a tar file. Traditional scanners would extract everything to disk. Redactyl streams the entire thing in memory."

**When showing Combined demo:**
> "In under a second, we scanned 37 files across archives, Helm charts, and Kubernetes manifests. This is what your CI/CD pipeline needs."

### 4. Compare with Alternatives

```bash
# Show what Gitleaks alone does
gitleaks detect --no-git --source test/integration/fixtures/helm/test-chart.tgz

# Result: Can't scan inside archives
# Redactyl: Finds secrets inside the .tgz
```

## Recording a Demo Video

### Setup
```bash
# Use asciinema for terminal recording
brew install asciinema

# Start recording
asciinema rec redactyl-demo.cast

# Run demo
./test/integration/demo.sh

# Stop recording (Ctrl+D)
```

### Upload
```bash
# Upload to asciinema.org
asciinema upload redactyl-demo.cast

# Or convert to GIF
npm install -g asciicast2gif
asciicast2gif redactyl-demo.cast redactyl-demo.gif
```

## Troubleshooting

### "Binary not found"
```bash
# Build it
make build
```

### "Gitleaks not found"
```bash
# macOS
brew install gitleaks

# Linux
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz
tar -xzf gitleaks_8.18.0_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/
```

### "No fixtures found"
```bash
# Generate them
./test/integration/scripts/generate-fixtures.sh
```

### Demo output looks weird
```bash
# Disable colors if presenting via screen share
NO_COLOR=1 ./test/integration/demo.sh
```

## Real-World Examples

Want to demo with actual artifacts instead of fixtures?

```bash
# Download a real Helm chart
helm repo add bitnami https://charts.bitnami.com/bitnami
helm pull bitnami/wordpress

# Scan it
./bin/redactyl scan --helm wordpress-*.tgz

# Get a real Docker image
docker pull nginx:latest
docker save nginx:latest -o nginx.tar

# Scan it
./bin/redactyl scan --containers nginx.tar
```

## Integration with CI/CD Demo

Show how it works in a CI pipeline:

```bash
# Create a .github/workflows/scan.yml
cat > .github/workflows/scan.yml << 'EOF'
name: Security Scan

on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Redactyl
        run: |
          wget https://github.com/redactyl/redactyl/releases/download/v1.0.0/redactyl-linux-amd64
          chmod +x redactyl-linux-amd64
          ./redactyl-linux-amd64 scan --helm --k8s --fail-on high
EOF
```

## Questions During Demo?

**Q: "How fast is it on large repos?"**
A: Run the combined demo - 37 files in < 1 second. Scales linearly.

**Q: "Can it scan my private Helm charts?"**
A: Yes, point it at your charts directory or .tgz files. Works with any Helm chart.

**Q: "Does it replace Gitleaks?"**
A: No, it uses Gitleaks for detection! We focus on deep artifact intelligence - streaming archives, OCI images, Helm charts - places Gitleaks can't reach alone.

**Q: "What about false positives?"**
A: All detections come from Gitleaks's battle-tested rules. You can customize with `.gitleaks.toml`.

**Q: "Can I use this in production?"**
A: Absolutely! These demos use the same code that runs in production. Just point it at your actual artifacts.

## Next Steps

- **Try it yourself:** `./test/integration/demo.sh`
- **Read the docs:** `../../README.md`
- **Run real tests:** `./test/integration/run-tests.sh`
- **Integrate with CI:** See `.github/workflows/integration-tests.yml`

---

**Demo Duration:** ~2 minutes
**Preparation Time:** 30 seconds (first run)
**Wow Factor:** High 🚀
