# Getting Started with Redactyl Development

**For developers working on Redactyl - the deep artifact scanner for cloud-native environments**

**Last Updated:** 2025-10-28

---

## Quick Context

**Read these first:**
1. `/CLAUDE.md` - Strategic context, decisions, and project direction
2. `/ROADMAP.md` - Product roadmap with quarterly milestones
3. `/docs/IMPLEMENTATION_PLAN.md` - Technical implementation history

**TL;DR:** Redactyl is a specialized deep artifact scanner powered by Gitleaks. We scan container images, Helm charts, K8s manifests, and complex nested artifacts where traditional scanners can't reach.

---

## Current State (Q1 2025 Complete ✅)

### What Works Today
- ✅ Gitleaks-powered secret detection (via scanner interface)
- ✅ Archive streaming (zip, tar, tgz) without disk extraction
- ✅ Container image scanning (Docker save format + OCI)
- ✅ Helm chart scanning (.tgz and directories)
- ✅ Kubernetes manifest scanning (auto-detection)
- ✅ Virtual paths for nested artifacts (`archive::layer::file`)
- ✅ SARIF output, JSON output, remediation commands
- ✅ Rich layer context (OCI support, BuildLayerContext)
- ✅ Config precedence: CLI > local .redactyl.yaml > global config
- ✅ Comprehensive integration tests (E2E with real Gitleaks)

### Current Focus (Q2 2025)
- 🎯 Registry integration (Docker Hub, GCR, ECR, ACR)
- 🎯 CI/CD platform integrations
- 🎯 Webhook automation
- 🎯 Performance optimization (caching, parallel scanning)

### Technology Stack
- Go 1.25+
- Gitleaks binary (detection engine)
- OCI Image Spec v1 (container scanning)
- Helm (chart scanning)
- Kubernetes YAML parsing

---

## Development Setup

### Prerequisites
```bash
# Go 1.25+
go version

# Gitleaks binary (for testing integration)
brew install gitleaks  # macOS
# or download from https://github.com/gitleaks/gitleaks/releases

# Make
make --version
```

### Clone and Build
```bash
git clone https://github.com/redactyl/redactyl.git
cd redactyl

# Build binary
make build

# Run tests
make test

# Run linter
make lint

# Build and run
./bin/redactyl scan --help
```

### Project Structure
```
redactyl/
├── cmd/redactyl/          # CLI commands
│   ├── scan.go           # Main scan command
│   ├── fix.go            # Remediation commands
│   └── purge.go          # History rewriting
├── internal/
│   ├── artifacts/        # 🌟 Core artifact streaming (keep & enhance)
│   │   ├── artifacts.go  # Archive/container scanning
│   │   └── ...
│   ├── detectors/        # ❌ Custom detectors (will be removed)
│   ├── scanner/          # ✨ NEW: Scanner interface & Gitleaks integration
│   ├── engine/           # Scan orchestration
│   ├── config/           # Configuration management
│   └── types/            # Shared types
├── pkg/core/             # Public Go API
├── docs/                 # Documentation
│   ├── IMPLEMENTATION_PLAN.md  # Detailed dev plan
│   └── deep-scanning.md        # Artifact scanning guide
├── CLAUDE.md             # 🎯 Project context (read this!)
└── ROADMAP.md            # Product roadmap
```

---

## Current Development Focus: Q2 2025 - Registry Integration

**Goal:** Enable scanning of container registries without pulling images (Weeks 13-17)

**Branch:** `main` (Q1 complete, ready for Q2 work)

### Getting Started with Q2 Development

#### Milestone 2.1: Docker Registry Integration

**What to build:**
1. Registry connector framework (`internal/registry/`)
2. Docker Hub, GCR, ECR, ACR API integration
3. Layer streaming via registry API
4. Layer cache (content-addressed)
5. CLI commands: `redactyl scan-registry`, `redactyl scan-image --registry`

**How to start:**
```bash
# Create feature branch
git checkout main
git pull origin main
git checkout -b feature/registry-integration

# Create registry package
mkdir -p internal/registry
touch internal/registry/client.go
touch internal/registry/dockerhub.go
touch internal/registry/gcr.go

# Reference the roadmap
less ROADMAP.md  # See Q2 Milestone 2.1
```

**Key Technical Challenges:**
- Streaming tar layers from HTTP without downloading full blob
- Layer caching strategy (SHA256-based deduplication)
- Authentication for private registries (Docker config, tokens)
- Parallel scanning of multiple images

**Reference Docs:**
- [Docker Registry HTTP API V2](https://docs.docker.com/registry/spec/api/)
- [OCI Distribution Spec](https://github.com/opencontainers/distribution-spec)

### For New Contributors

If you're new to the project, start with smaller tasks:

**Good First Issues:**
1. Add more integration tests for Helm/K8s scanning
2. Improve error messages (user-facing strings)
3. Add benchmarks for artifact scanning performance
4. Documentation improvements (examples, tutorials)
5. Implement Gitleaks auto-download (deferred from Q1)

**Where to look:**
- `cmd/redactyl/e2e_helm_k8s_test.go` - Add more test cases
- `internal/artifacts/` - Add performance benchmarks
- `docs/` - Improve user documentation

---

## Testing Guidelines

### Unit Tests (Fast, ~10s)
Component-level Go tests for individual packages.

```bash
# Test specific package
go test ./internal/scanner/gitleaks -v

# Test with coverage
go test ./internal/scanner/... -cover

# Run all unit tests
make test
```

### Integration Tests (Real Artifacts, ~2-5min)
**NEW:** End-to-end tests with real artifacts to validate the entire system.

```bash
# Run all integration tests
./test/integration/run-tests.sh

# Run specific category
./test/integration/run-tests.sh baseline    # Fast, always run first
./test/integration/run-tests.sh helm        # Helm charts
./test/integration/run-tests.sh k8s         # Kubernetes manifests
./test/integration/run-tests.sh containers  # Docker images

# Verbose output
VERBOSE=1 ./test/integration/run-tests.sh
```

**Why integration tests?**
- Test with real Gitleaks binary (not mocked)
- Verify actual OCI images, Helm charts, K8s YAML
- Catch edge cases Go unit tests miss
- Performance validation with large artifacts
- Regression detection from real-world scenarios

**Read:** [`test/integration/TESTING_GUIDE.md`](../../test/integration/TESTING_GUIDE.md) for comprehensive guide

### Go Integration Tests (Legacy)
```bash
# E2E CLI tests in Go (still useful for quick checks)
make build
go test ./cmd/redactyl -v -run TestCLI_Helm_Chart_Directory

# Test with real artifacts
./bin/redactyl scan --archives testdata/sample.zip
./bin/redactyl scan --containers testdata/sample.tar
```

### Manual Testing Checklist
Create this test suite as you develop:

```bash
# 1. Basic scan
echo 'GITHUB_TOKEN=ghp_1234567890' > /tmp/test.txt
./bin/redactyl scan /tmp/test.txt

# 2. Archive scanning
zip /tmp/test.zip /tmp/test.txt
./bin/redactyl scan --archives /tmp/test.zip

# 3. Container scanning
# (requires Docker)
docker pull alpine:latest
docker save alpine:latest > /tmp/alpine.tar
./bin/redactyl scan --containers /tmp/alpine.tar

# 4. Nested archives
# Create zip inside tar
./bin/redactyl scan --archives /tmp/nested.tar

# 5. JSON output
./bin/redactyl scan /tmp/test.txt --json

# 6. SARIF output
./bin/redactyl scan /tmp/test.txt --sarif
```

---

## Common Development Tasks

### Adding a New Feature
1. Check if it aligns with `/ROADMAP.md` priorities
2. Create feature branch: `feature/short-description`
3. Update `/CLAUDE.md` if it affects strategy
4. Write tests first (TDD preferred)
5. Implement feature
6. Update documentation
7. Open PR with clear description

### Debugging
```bash

./bin/redactyl scan --verbose /tmp/test.txt

# Use delve debugger
dlv debug . -- scan /tmp/test.txt

# Print intermediate values
# Add log.Printf() statements liberally during development
```

### Performance Profiling
```bash
# CPU profile
go test ./internal/artifacts -cpuprofile=cpu.prof -bench=.
go tool pprof cpu.prof

# Memory profile
go test ./internal/artifacts -memprofile=mem.prof -bench=.
go tool pprof mem.prof

# Benchmark specific function
go test ./internal/scanner/gitleaks -bench=BenchmarkScan -benchmem
```

---

## Code Style Guidelines

### Go Best Practices
- Follow standard Go formatting (`gofmt`, `goimports`)
- Use meaningful variable names (no single-letter except loops)
- Keep functions small (< 50 lines ideal)
- Document all exported functions and types
- Handle errors explicitly (no `_` unless justified)

### Project-Specific Conventions

**Virtual Paths:**
```go
// Always use scanner.BuildVirtualPath()
virtualPath := scanner.BuildVirtualPath("archive.zip", "inner.tar", "file.txt")
// Result: "archive.zip::inner.tar::file.txt"
```

**Error Handling:**
```go
// Wrap errors with context
if err != nil {
    return fmt.Errorf("failed to scan %s: %w", path, err)
}
```

**Testing:**
```go
// Use testify for assertions
import (
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// require.* for fatal errors
require.NoError(t, err)

// assert.* for non-fatal assertions
assert.Equal(t, expected, actual)
```

---

## Documentation Standards

### When to Update Docs
- Adding a new CLI flag → update command help + README
- Adding a config option → update `docs/configuration.md`
- Changing behavior → update relevant doc + add migration note
- New feature → update README, add to CHANGELOG.md

### Doc Locations
- User-facing: `README.md`, `docs/*.md`
- Developer-facing: `CLAUDE.md`, `CONTRIBUTING.md`, inline code comments
- API: `pkg/core/` (godoc comments)

---

## Git Workflow

### Branch Strategy
- `main` - stable, always buildable
- `feature/*` - new features
- `fix/*` - bug fixes
- `docs/*` - documentation only

### Commit Messages
```
feat(scanner): add Gitleaks binary detection

- Implement BinaryManager for finding gitleaks binary
- Add auto-download from GitHub releases
- Add version checking
- Closes #123
```

Format: `<type>(<scope>): <subject>`

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`

### Pull Request Template
```markdown
## Description
Brief description of changes

## Related Issues
Closes #123

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Documentation
- [ ] README updated (if needed)
- [ ] CHANGELOG updated
- [ ] Inline docs added

## Checklist
- [ ] Code follows style guidelines
- [ ] No new linter warnings
- [ ] Backward compatible (or migration guide provided)
```

---

## Troubleshooting

### Gitleaks Binary Not Found
```bash
# Check if gitleaks is in PATH
which gitleaks

# Install locally for testing
brew install gitleaks  # macOS
# or download from GitHub releases

# For auto-download testing, remove cached binary
rm -rf ~/.redactyl/bin/gitleaks
```

### Tests Failing
```bash
# Run specific test with verbose output
go test ./internal/scanner/gitleaks -v -run TestSpecificTest

# Run tests without cache
go clean -testcache
go test ./...

# Check for race conditions
go test -race ./...
```

### Build Errors
```bash
# Clean and rebuild
make clean
make build

# Update dependencies
go mod tidy
go mod verify

# Check Go version
go version  # Should be 1.25+
```

---

## Resources

### Internal Docs
- `/CLAUDE.md` - Project strategy and context
- `/ROADMAP.md` - Product roadmap
- `/docs/IMPLEMENTATION_PLAN.md` - Technical implementation details
- `/docs/deep-scanning.md` - Artifact scanning guide

### External References
- [Gitleaks Documentation](https://github.com/gitleaks/gitleaks)
- [SARIF Spec](https://docs.oasis-open.org/sarif/sarif/v2.1.0/)
- [OCI Image Spec](https://github.com/opencontainers/image-spec)
- [Helm Chart Structure](https://helm.sh/docs/topics/charts/)

### Community
- GitHub Discussions: Planned
- Discord: Planned
- Email: Planned

---

## Next Steps

1. **Read strategic context:** `/CLAUDE.md`
2. **Understand the plan:** `/ROADMAP.md` and `/docs/IMPLEMENTATION_PLAN.md`
3. **Set up environment:** Install Go, Gitleaks, build project
4. **Start coding:** Begin with Phase 1, Week 1 tasks
5. **Ask questions:** Open GitHub discussion or check existing docs

**Current Priority:** Gitleaks integration (Phase 1, Weeks 1-4)

**Ready to start?**
```bash
git checkout -b feature/gitleaks-integration
mkdir -p internal/scanner/gitleaks
# Start with scanner interface (see IMPLEMENTATION_PLAN.md)
```

---

**Welcome to the team! Let's build the best artifact scanner for cloud-native environments.**
