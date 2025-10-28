# Redactyl - Project Context for Claude

**Last Updated:** 2025-10-28
**Status:** Q1 2025 Milestones Complete + Legacy Code Cleanup - Production Ready
**Branch:** `pivot-buildout` (7 commits ahead of main)

## Executive Summary

Redactyl is a **specialized deep artifact scanner** for cloud-native environments. We've successfully completed our strategic pivot from a general-purpose secret scanner to focusing on complex artifacts (containers, Helm charts, K8s manifests, archives) where secrets hide. We use **Gitleaks exclusively** for all secret detection and differentiate on artifact intelligence.

**Current State:** All Q1 2025 roadmap milestones completed + legacy code removed ✅
- **100% Gitleaks-based detection** - All legacy detector code removed
- Gitleaks integration with scanner abstraction
- OCI image format support with rich layer context
- Helm chart scanning (.tgz and directories)
- Kubernetes manifest scanning with auto-detection
- Full CLI and config system integration
- Integration test framework with 8/8 tests passing
- Clean codebase with no legacy regex/detector code

## Strategic Position

### Why This Works
- **Complementary to Gitleaks:** We enhance, not compete (Gitleaks scans repos, we scan artifacts)
- **Unique Value:** Streaming artifact scanning without disk extraction
- **Market Fit:** DevSecOps teams at cloud-native companies need this
- **Technical Moat:** Virtual path tracking, nested artifact handling, OCI format expertise

### Target Customers
- DevSecOps teams at cloud-native companies
- Kubernetes/Helm power users
- CI/CD pipeline operators
- Container security teams
- Compliance-focused enterprises

## Current Architecture (As of 2025-10-28)

### Detection Architecture: 100% Gitleaks

**Key Decision:** We removed ALL legacy detector code (`internal/detectors/` - 150+ files) and rely exclusively on Gitleaks for secret detection. This gives us:
- ✅ **Maintained patterns** - Gitleaks team keeps 200+ rules updated
- ✅ **Industry standard** - Battle-tested patterns from the Gitleaks community
- ✅ **Clean codebase** - No regex pattern maintenance burden
- ✅ **Clear positioning** - We're artifact intelligence, Gitleaks is pattern matching

**What we do:** Parse artifacts (Helm, K8s, OCI, archives) → feed content to Gitleaks → enrich findings with artifact context
**What Gitleaks does:** Pattern matching and secret detection

### Core Components

#### 1. Scanner Abstraction (`internal/scanner/`)
```go
// Scanner interface for pluggable detection engines
type Scanner interface {
    Scan(path string, data []byte) ([]types.Finding, error)
    ScanWithContext(ctx ScanContext, data []byte) ([]types.Finding, error)
    Version() (string, error)
}

// ScanContext preserves artifact metadata
type ScanContext struct {
    VirtualPath string            // e.g., "chart.tgz::templates/secret.yaml"
    RealPath    string            // Temp file path on disk
    Metadata    map[string]string // Artifact-specific metadata
}
```

**Implementation:** Currently only Gitleaks scanner exists. The interface allows future scanners but Gitleaks is sufficient.

#### 2. Gitleaks Integration (`internal/scanner/gitleaks/`)
- **Binary Manager:** Auto-detect in PATH, version checking, auto-download
- **Scanner Implementation:** Temp file handling, report-path JSON parsing
- **Finding Conversion:** Maps Gitleaks JSON → Redactyl types.Finding
- **Virtual Path Remapping:** Preserves artifact context through scanning
- **Metadata Enrichment:** Adds gitleaks_rule_id to finding metadata

#### 3. Artifact Scanning (`internal/artifacts/`)

**OCI Support (`oci.go`, 289 lines):**
- Full OCI Image Spec v1 implementation
- OCIManifest, OCIIndex, OCIConfig parsing
- LayerContext with Dockerfile commands, timestamps, architecture
- Multi-arch image detection
- Format detection (OCI vs Docker)

**Helm Support (`helm.go`, 392 lines):**
- Scan .tgz archives and unpacked directories
- Parse Chart.yaml, values.yaml metadata
- Deep scan templates/, secrets, configmaps
- Virtual paths: `mychart.tgz::templates/secret.yaml`

**Kubernetes Support (`k8s.go`, 289 lines):**
- Auto-detect K8s YAML by structure and naming
- Multi-document YAML parsing
- Identify sensitive resources (Secrets, ConfigMaps, Pod specs)
- Extract K8s metadata (kind, apiVersion, namespace)

**Existing Features (Kept):**
- Archives: zip, tar, tgz streaming
- Containers: Docker saved tarballs with layer scanning
- IaC: Terraform state, kubeconfigs
- Guardrails: bytes, entries, depth, time budgets

#### 4. Engine Integration (`internal/engine/engine.go`)
- `ScanHelm` and `ScanK8s` flags
- Integrated with existing artifact scanning pipeline
- Uses scanner interface for all detection
- Guardrails applied across all artifact types

#### 5. CLI (`cmd/redactyl/scan.go`)
```bash
# New flags added
--helm                # Scan Helm charts (.tgz and directories)
--k8s                 # Scan Kubernetes manifests (YAML files)

# Config file support
helm: true
k8s: true
gitleaks:
  config: .gitleaks.toml
  auto_download: true
  version: latest
```

### What We Removed
- ❌ All 82 custom detectors (4,066 LOC deleted)
- ❌ Custom confidence scoring logic (replaced by Gitleaks + mapping)
- ❌ Detector-specific CLI flags (--enable, --disable)

## Recent Implementation (Last Session)

### Phase 1: Gitleaks Integration (Completed)
**Commits:**
- `a152f5c` - Setup pivot for artifact scanning
- `b10b289` - feat(scanner): add Gitleaks integration foundation
- `7329513` - feat(engine): integrate Gitleaks scanner into engine
- `39a893d` - fix(scanner): use report-path for Gitleaks JSON output and add severity mapping

**Deliverables:**
- Scanner interface abstraction
- Gitleaks binary manager
- Virtual path preservation via ScanContext
- Report-path fix (Gitleaks requires `--report-path` for JSON)
- Confidence → severity mapping for `--fail-on` thresholds

### Phase 2: Cloud-Native Scanning (Completed)
**Commits:**
- `622ca9e` - feat(artifacts): add OCI, Helm, and Kubernetes scanning support
- `d8c2993` - feat(engine,cli): integrate Helm and Kubernetes scanning into engine and CLI
- `a130703` - docs: update README and ROADMAP with Phase 2 completion

**Deliverables:**
- OCI image manifest parsing (5 files, 1,381 lines)
- Helm chart scanning (both .tgz and directories)
- Kubernetes manifest scanning (auto-detection)
- Full engine and CLI integration
- 4 E2E integration tests
- Comprehensive documentation updates

### Test Coverage
- ✅ 16 artifact tests (OCI, Helm, K8s parsing)
- ✅ 4 E2E integration tests (CLI with Gitleaks)
- ✅ All existing tests passing
- ✅ Full test suite: `go test ./...` passes

## Usage Examples

```bash
# Scan Helm charts
redactyl scan --helm -p ./my-k8s-project

# Scan Kubernetes manifests
redactyl scan --k8s -p ./manifests

# Scan everything (containers + Helm + K8s)
redactyl scan --containers --helm --k8s --archives -p ./

# With guardrails
redactyl scan --helm --k8s \
  --max-archive-bytes 67108864 \
  --scan-time-budget 5s \
  --global-artifact-budget 30s

# Typical CI/CD scan
redactyl scan --archives --containers --helm --k8s \
  --max-depth 3 \
  --scan-time-budget 10s
```

## Product Roadmap Status

### Q1 2025: Foundation & Gitleaks Integration ✅ COMPLETED
- [x] Milestone 1.1: Gitleaks Integration (Weeks 1-4)
- [x] Milestone 1.2: Enhanced Container Scanning (Weeks 5-8)
- [x] Milestone 1.3: Kubernetes & Helm Support (Weeks 9-12)

**All success metrics achieved:**
- ✅ Gitleaks integration with scanner abstraction
- ✅ OCI image format support with rich layer context
- ✅ Helm chart scanning (.tgz and directories)
- ✅ Kubernetes manifest scanning with auto-detection
- ✅ All tests passing
- ✅ Documentation complete

### Q2 2025: Registry Integration & Scale (NEXT)
**Focus Areas:**
1. **Docker Registry Integration**
   - Stream layers via registry API (no pull)
   - Cache layer scans (content-addressed)
   - Support Docker Hub, GCR, ECR, ACR

2. **CI/CD Artifact Scanning**
   - Scan build outputs (JARs, wheels, npm builds)
   - GitHub Actions workflow
   - GitLab CI job template
   - Policy enforcement (block deployments)

3. **Webhook & Automation**
   - Webhook receiver for registry push events
   - Slack/PagerDuty notifications
   - Scheduled re-scans
   - Drift detection

### Q3 2025: Enterprise Features
- Web dashboard (React + Go API)
- Policy engine (YAML DSL)
- SSO integration (SAML, OIDC)
- Multi-tenancy + RBAC

### Q4 2025: Advanced Scanning
- VM image scanning (AMI, VMDK, QCOW2)
- Dependency tree scanning (node_modules, vendor/)
- Advanced analytics dashboard
- API for programmatic access

## Next Session TODO List

### Immediate Tasks (Next Session)
1. **Merge `pivot-buildout` to `main`**
   - Review all 7 commits
   - Squash if needed or keep detailed history
   - Update main branch with Q1 completion

2. **Prepare Release v1.0**
   - Update CHANGELOG.md with all Q1 features
   - Bump version from 0.1.0 to 1.0.0
   - Create release notes
   - Tag release: `git tag v1.0.0`

3. **Post-Launch Documentation**
   - Create `docs/gitleaks-integration.md` (how it works)
   - Create migration guide (for anyone using detectors)
   - Update CONTRIBUTING.md
   - Create detector ID mapping table (old → Gitleaks rules)

4. **Performance & Benchmarking**
   - Add benchmarks for artifact scanning
   - Test with large Helm charts (100+ templates)
   - Test with large container images (10GB+)
   - Document performance characteristics

### Short-Term (Next 1-2 Weeks)
5. **Community & Marketing**
   - Write blog post: "Why Redactyl uses Gitleaks"
   - Create announcement for HackerNews/Reddit
   - Update GitHub description and topics
   - Create Twitter/LinkedIn posts

6. **Q2 Planning**
   - Detailed design for registry integration
   - Spike: Docker Registry API client
   - Prototype: Stream layers without pulling
   - Research: GitHub Actions marketplace listing

7. **Technical Debt**
   - Implement Gitleaks auto-download (currently placeholder)
   - Add more OCI format tests (edge cases)
   - Improve error messages for Gitleaks failures
   - Add telemetry opt-in (usage stats)

### Medium-Term (Next 1-2 Months)
8. **Start Q2 Milestone 2.1: Registry Integration**
   - Design registry connector framework
   - Implement Docker Hub API client
   - Add caching for layer scans
   - CLI: `redactyl scan-registry gcr.io/myproject/*`

9. **CI/CD Templates**
   - GitHub Actions workflow template
   - GitLab CI YAML template
   - CircleCI config template
   - Jenkins pipeline example

10. **Enterprise Features Prep**
    - Design policy engine DSL
    - Prototype web UI (React + Vite)
    - Plan Go API for dashboard backend
    - Research hosting options (AWS, GCP, self-hosted)

## Working Status Summary

### What Works Now
✅ Full artifact scanning (archives, containers, Helm, K8s, IaC)
✅ Gitleaks integration with virtual path preservation
✅ CLI with all flags and config file support
✅ Multiple output formats (table, JSON, SARIF)
✅ Guardrails and time budgets
✅ Comprehensive test coverage
✅ Documentation complete

### What's Incomplete
⚠️ Gitleaks auto-download (placeholder exists, needs implementation)
⚠️ Registry integration (Q2 feature)
⚠️ Web dashboard (Q3 feature)
⚠️ Policy engine (Q3 feature)

### Known Issues
- None currently - all tests passing ✅

### Testing Strategy

**Unit Tests:** Go tests for individual components (~10s to run all)
- Location: `internal/*/` with `*_test.go` files
- Coverage: Good for component testing
- Limitation: May miss integration issues, real artifact edge cases

**Integration Tests:** Real-world validation with actual artifacts (~2-5min)
- Location: `test/integration/`
- Purpose: End-to-end validation with real Gitleaks binary, OCI images, Helm charts
- Categories: baseline, archives, containers, helm, k8s, performance, combined
- Run: `./test/integration/run-tests.sh`
- CI: Runs on every PR (fast suite), push to main (full suite), nightly (with benchmarks)
- Documentation: `test/integration/TESTING_GUIDE.md`

**Why both?**
- Unit tests: Fast feedback during development
- Integration tests: Confidence the full system works with real artifacts

**Example workflow:**
```bash
# During development
go test ./internal/helm/...

# Before commit
make test                              # All unit tests
./test/integration/run-tests.sh baseline  # Fast integration smoke test

# Before PR
./test/integration/run-tests.sh       # Full integration suite
```

## Technical Decisions Log

### Recent Decisions (2025-10-28)
- ✅ Keep confidence → severity mapping (users need `--fail-on` for CI/CD)
- ✅ Use report-path for Gitleaks JSON (stdout doesn't work)
- ✅ Map entropy to confidence scores (>4.5 = high, 3.5-4.5 = medium, <3.5 = low)
- ✅ Test patterns must have medium entropy for Gitleaks compatibility
- ✅ Virtual path format: `artifact::nested::file` using "::" separator

### Original Decisions (2025-10-27)
- ✅ Pivot to deep artifact scanning
- ✅ Integrate Gitleaks instead of competing
- ✅ Keep pre-launch, no v1.0 migration needed
- ✅ Target DevSecOps/cloud-native market

### Architecture Decisions
- ✅ Scanner interface abstraction (enables pluggable engines)
- ✅ ScanContext for virtual path preservation
- ✅ Streaming architecture (no disk extraction)
- ✅ Guardrails for safety (bytes, entries, depth, time)

## Git Repository Status

**Branch:** `pivot-buildout` (7 commits)
**Status:** Ready to merge to main

```
a130703 - docs: update README and ROADMAP with Phase 2 completion
d8c2993 - feat(engine,cli): integrate Helm and Kubernetes scanning
622ca9e - feat(artifacts): add OCI, Helm, and Kubernetes scanning support
39a893d - fix(scanner): use report-path and add severity mapping
7329513 - feat(engine): integrate Gitleaks scanner into engine
b10b289 - feat(scanner): add Gitleaks integration foundation
a152f5c - setup pivot for artifact scanning
```

**Stats:**
- Files changed: 15+
- Lines added: ~2,900 (production code)
- Lines deleted: ~50 (mainly docs)
- Tests added: 20+
- Documentation files: 4 (README, ROADMAP, CLAUDE.md, .redactyl.example.yaml)

## Key Metrics (Current)

### Technical
- Artifact types supported: 6 (archives, containers, Helm, K8s, IaC, nested)
- Test coverage: 20+ tests, 100% pass rate
- Scanner abstraction: Fully implemented
- Gitleaks integration: Complete with virtual paths

### Business (Pre-launch)
- GitHub stars: ~200 (before pivot)
- Weekly active scans: N/A (pre-release)
- Paying customers: 0 (OSS first)
- Contributors: 1 (pre-community)

## Communication Style

When working on this project:
- **Be direct** - No fluff, just facts
- **Technical depth** - This is for engineers
- **Pragmatic** - Focus on shipping, not perfection
- **Collaborative** - We're building in the open

## Notes for Future Claude Sessions

### Before Starting Work
1. **Read this file first** - It's the source of truth
2. **Check the TODO list above** - Priorities are clear
3. **Review recent commits** - `git log --oneline | head -10`
4. **Run tests** - Ensure everything still works: `go test ./...`

### When Resuming Work
- Current branch: `pivot-buildout`
- Next milestone: Merge to main + Release v1.0
- Focus area: Q2 planning (registry integration)
- Status: Q1 complete, ready for launch

### When Suggesting Features
**Ask yourself:**
1. Does this strengthen our artifact scanning differentiation?
2. Could Gitleaks already do this? (If so, use Gitleaks)
3. Does this fit cloud-native DevSecOps target market?
4. Is this a Q2, Q3, or Q4 feature? (Don't jump ahead)

### When in Doubt
- Prioritize artifact scanning depth over breadth
- Prefer integration over reinvention
- Focus on enterprise pain points (compliance, scale, automation)
- Check ROADMAP.md for strategic direction

## Resources & Links

### Documentation
- README.md - User-facing documentation
- ROADMAP.md - Product roadmap and milestones
- IMPLEMENTATION_PLAN.md - Technical implementation details
- GETTING_STARTED_DEV.md - Developer onboarding

### Competition
- Gitleaks: https://github.com/gitleaks/gitleaks (partner, not competitor)
- TruffleHog: https://github.com/trufflesecurity/trufflehog
- GitGuardian: https://www.gitguardian.com/

### Technical References
- OCI Image Spec: https://github.com/opencontainers/image-spec
- Gitleaks Config: https://github.com/gitleaks/gitleaks#configuration
- SARIF 2.1.0: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
- Docker Registry API: https://docs.docker.com/registry/spec/api/

---

*This document is living context. Update it after every major milestone.*
*Last major update: 2025-10-28 (Q1 completion)*
