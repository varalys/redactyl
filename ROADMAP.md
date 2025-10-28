# Redactyl Product Roadmap

**Vision:** The definitive deep artifact scanner for cloud-native environments

**Last Updated:** 2025-10-28

---

## Strategic Direction

We're building a **specialized artifact scanner** that finds secrets in the complex, nested structures of modern cloud-native deployments - places where traditional scanners can't reach.

**Core Philosophy:**
- Use Gitleaks for detection patterns (don't reinvent regex)
- Differentiate on artifact intelligence (streaming, context, depth)
- Target DevSecOps at cloud-native companies
- Privacy-first, enterprise-ready

---

## Q1 2025: Foundation & Gitleaks Integration

**Theme:** "Build the artifact scanning platform"

### Milestone 1.1: Gitleaks Integration (Weeks 1-4) ✅ COMPLETED
**Goal:** Replace custom detectors with Gitleaks binary integration

**Deliverables:**
- [x] `internal/scanner/gitleaks.go` package
  - Binary detection (check $PATH, common locations)
  - Auto-download mechanism placeholder
  - Version compatibility checking
- [x] Virtual path remapping
  - Map temp file paths back to artifact origins
  - Preserve `archive.zip::layer::file.txt` format via ScanContext
- [x] Config system refactor
  - Support `.gitleaks.toml` alongside `.redactyl.yml`
  - Gitleaks config with auto_download, version, config_path
- [x] Integration tests with real Gitleaks binary
- [x] Scanner interface abstraction (Scanner, ScanContext)
- [x] Report-path fix for JSON output
- [x] Severity mapping from confidence scores

**Success Metrics:**
- ✅ All tests passing with Gitleaks (scanner, engine, CLI)
- ✅ Scan performance maintained
- ✅ Zero detector maintenance code

### Milestone 1.2: Enhanced Container Scanning (Weeks 5-8) ✅ COMPLETED
**Goal:** Best-in-class Docker image scanning

**Deliverables:**
- [x] OCI format support (full OCI Image Spec v1)
  - OCIManifest, OCIIndex, OCIConfig parsing
  - Multi-arch image detection via indexes
  - Format detection (OCI vs Docker)
- [x] Layer context enhancement
  - Show Dockerfile command that created layer
  - Layer size and creation timestamp
  - Parent layer tracking
  - Architecture and OS metadata
- [ ] Container registry manifest inspection (deferred to Q2)
  - Parse remote manifests without downloading
  - Show which tags contain findings
- [x] Existing streaming architecture maintained

**Success Metrics:**
- ✅ Full OCI spec implementation with tests
- ✅ Rich layer context (BuildLayerContext function)
- ✅ Zero disk extraction (streaming only)

### Milestone 1.3: Kubernetes & Helm Support (Weeks 9-12) ✅ COMPLETED
**Goal:** Native understanding of K8s secrets

**Deliverables:**
- [x] Helm chart scanning
  - Parse Chart.yaml, values.yaml for metadata
  - Scan all templates/ files
  - Scan packaged charts (.tgz) without extraction
  - CLI flag: `--helm`
- [x] Kubernetes manifest detection
  - Parse K8s YAML (single and multi-doc)
  - Detect sensitive resources (Secret, ConfigMap, Pod specs)
  - Auto-detect K8s files by structure and naming
  - CLI flag: `--k8s`
- [x] Full engine and CLI integration
  - Config file support (helm: true, k8s: true)
  - Precedence: CLI > local > global config
  - Virtual path support for nested files
- [x] Comprehensive integration tests (4 E2E tests)
- [ ] Kustomize support (deferred - low priority)
- [ ] Base64 decode in K8s Secrets (deferred - handled by Gitleaks)

**Success Metrics:**
- ✅ Scan both .tgz and unpacked Helm charts
- ✅ Parse multi-document K8s YAML
- ✅ All integration tests passing
- ✅ Virtual paths show artifact origins

### Q1 Deliverables Summary
✅ Gitleaks integration complete
✅ Custom detectors deprecated/removed
✅ Enhanced container scanning
✅ Helm + Kubernetes support
✅ Updated documentation
- Blog post: "Why Redactyl uses Gitleaks"

---

## Q2 2025: Registry Integration & Scale

**Theme:** "Scan where secrets are created"

### Milestone 2.1: Docker Registry Integration (Weeks 13-17)
**Goal:** Scan images in registries without pulling

**Deliverables:**
- [ ] Registry connector framework
  - Docker Hub API integration
  - Google Container Registry (GCR)
  - AWS Elastic Container Registry (ECR)
  - Azure Container Registry (ACR)
- [ ] Efficient scanning
  - Stream layers via registry API
  - Cache layer scans (content-addressed)
  - Parallel multi-image scanning
- [ ] CLI commands
  - `redactyl scan-registry gcr.io/myproject/*`
  - `redactyl scan-image myapp:latest --registry`
  - Wildcard tag support

**Success Metrics:**
- Scan 100-image registry in < 10 minutes
- 80% cache hit rate for common base layers
- Support 4 major registry providers

### Milestone 2.2: CI/CD Artifact Scanning (Weeks 18-21)
**Goal:** Scan build outputs before deployment

**Deliverables:**
- [ ] Build artifact detection
  - JARs, WARs (Java)
  - Wheels, eggs (Python)
  - Gems (Ruby)
  - npm/yarn build outputs
- [ ] CI/CD platform integrations
  - GitHub Actions workflow
  - GitLab CI job template
  - Jenkins plugin (optional)
  - CircleCI orb (optional)
- [ ] Policy enforcement
  - Block deployments with high-severity findings
  - Configurable thresholds
  - Exemption/waiver system

**Success Metrics:**
- Integrate with 3+ CI/CD platforms
- Scan time < 5% of total build time
- < 1% false positive rate causing build failures

### Milestone 2.3: Webhook & Automation (Weeks 22-26)
**Goal:** Real-time scanning on events

**Deliverables:**
- [ ] Webhook receiver service
  - Scan on registry push events
  - Scan on Helm chart publish
  - Scan on artifact upload (generic)
- [ ] Notification system
  - Slack integration
  - PagerDuty for high-severity
  - Email alerts
  - Webhook callbacks
- [ ] Scan scheduling
  - Periodic re-scans of registries
  - Scheduled baseline updates
  - Drift detection (new secrets in old images)

**Success Metrics:**
- < 5 second webhook response time
- 99.9% webhook processing reliability
- Support 1000+ webhooks/hour

### Q2 Deliverables Summary
✅ Registry scanning (4 providers)
✅ CI/CD integrations (3+ platforms)
✅ Webhook automation
✅ First 10 paying customers
- Case study with design partner

---

## Q3 2025: Enterprise Features & Scale

**Theme:** "Production-ready for enterprises"

### Milestone 3.1: Web Dashboard (Weeks 27-31)
**Goal:** Simple UI for artifact visualization

**Deliverables:**
- [ ] Frontend application (React + TypeScript)
  - Artifact timeline view
  - Finding details with virtual paths
  - Drill-down into layers/archives
  - Filter by severity, type, date
- [ ] Backend API (Go)
  - Ingest scan results (JSON upload)
  - Query API for dashboard
  - User authentication (JWT)
- [ ] Deployment options
  - Docker Compose for self-hosted
  - Kubernetes Helm chart
  - Cloud deployment templates (AWS, GCP, Azure)

**Success Metrics:**
- Load 10,000 findings in < 2 seconds
- Support 100 concurrent users
- 95%+ uptime for hosted option

### Milestone 3.2: Policy Engine (Weeks 32-36)
**Goal:** Enforce security policies across artifacts

**Deliverables:**
- [ ] Policy DSL (YAML-based)
  - Define allowed/blocked secrets by type
  - Severity thresholds
  - Exemptions by path/artifact
- [ ] Policy evaluation
  - Evaluate during scan
  - Block/warn/allow actions
  - Audit trail of decisions
- [ ] Pre-built policies
  - PCI-DSS compliance
  - SOC2 requirements
  - Kubernetes best practices
  - OWASP top 10

**Success Metrics:**
- Evaluate 1000 findings in < 100ms
- Support 50+ policy rules per scan
- Zero policy evaluation errors

### Milestone 3.3: Multi-Tenancy & SSO (Weeks 37-40)
**Goal:** Enterprise-grade access control

**Deliverables:**
- [ ] Multi-tenant architecture
  - Organization/workspace isolation
  - Shared base layers (performance)
  - Per-tenant quotas
- [ ] SSO integration
  - SAML 2.0
  - OpenID Connect (OIDC)
  - Google Workspace, Okta, Azure AD
- [ ] RBAC (Role-Based Access Control)
  - Predefined roles (admin, viewer, auditor)
  - Custom role creation
  - Resource-level permissions

**Success Metrics:**
- Support 50+ organizations
- < 1 second SSO login time
- 100% audit log coverage

### Q3 Deliverables Summary
✅ Web dashboard (self-hosted + cloud)
✅ Policy engine with compliance packs
✅ SSO + RBAC
✅ 50 paying customers
- Security whitepaper
- SOC2 Type 1 certification (if hosted)

---

## Q4 2025: Advanced Scanning & Ecosystem

**Theme:** "Cover every artifact type"

### Milestone 4.1: VM Image Scanning (Weeks 41-44)
**Goal:** Scan virtual machine images

**Deliverables:**
- [ ] VM image format support
  - Amazon AMI (.ami)
  - VMware VMDK
  - QCOW2 (QEMU)
  - VHD (Azure)
- [ ] Filesystem parsing
  - ext4, xfs, NTFS
  - Mount-free scanning (direct read)
  - Selective file extraction
- [ ] OS-specific scanning
  - Linux: /etc/passwd, /root/.ssh, systemd units
  - Windows: Registry, IIS configs
  - Find SSH keys, database configs

**Success Metrics:**
- Scan 10GB VM image in < 5 minutes
- Support 4 major formats
- Detect secrets in 90%+ of standard locations

### Milestone 4.2: Dependency Scanning (Weeks 45-48)
**Goal:** Scan package dependencies for embedded secrets

**Deliverables:**
- [ ] Dependency tree analysis
  - node_modules (npm/yarn)
  - vendor/ (Go)
  - site-packages (Python)
  - gems (Ruby)
- [ ] Selective scanning
  - Skip known-safe packages (allowlist)
  - Focus on custom/internal packages
  - Dependency graph visualization
- [ ] Supply chain insights
  - Show which dependency introduced secret
  - Transitive dependency attribution
  - Vulnerability + secret correlation

**Success Metrics:**
- Scan 500MB node_modules in < 2 minutes
- 95% reduction in false positives vs full scan
- Support 4 major package managers

### Milestone 4.3: Advanced Analytics (Weeks 49-52)
**Goal:** Insights and trends across scans

**Deliverables:**
- [ ] Trend analysis
  - Secret count over time
  - MTTR (mean time to remediation)
  - Top offending artifacts
- [ ] Risk scoring
  - Combine severity, exposure, age
  - Prioritize remediation
  - Risk heatmaps
- [ ] Reporting
  - Executive summary reports
  - Compliance evidence packs
  - Custom report builder
- [ ] API for programmatic access
  - REST API with OpenAPI spec
  - GraphQL endpoint (optional)
  - Webhook callbacks

**Success Metrics:**
- Generate report for 10,000 findings in < 5 seconds
- API latency < 100ms (p95)
- Support 100 API requests/second

### Q4 Deliverables Summary
✅ VM image scanning
✅ Dependency tree analysis
✅ Advanced analytics dashboard
✅ 100+ paying customers
- KubeCon presentation
- Year-in-review blog post

---

## 2026 Preview: Future Directions

### Registry Marketplace
- List Redactyl on AWS Marketplace, GCP Marketplace
- Pre-packaged AMIs and VM images
- One-click enterprise deployment

### Secret Rotation Integration
- Detect + rotate in one workflow
- Integration with HashiCorp Vault, AWS Secrets Manager
- Auto-remediation workflows

### Machine Learning
- Anomaly detection for unusual secrets
- Predict false positives
- Smart secret classification

### Compliance Expansion
- FedRAMP compliance
- HIPAA compliance pack
- Financial services (PCI-DSS Level 1)

### Community Ecosystem
- Plugin marketplace
- Custom detector contributions
- Community-driven policy packs

---

## Success Metrics (2025)

### Technical KPIs
| Metric | Q1 | Q2 | Q3 | Q4 |
|--------|----|----|----|----|
| Artifact types supported | 5 | 8 | 10 | 12 |
| Avg scan time (1GB artifact) | 30s | 20s | 15s | 10s |
| False positive rate | 5% | 3% | 2% | 1% |
| Registry providers | 0 | 4 | 4 | 6 |

### Business KPIs
| Metric | Q1 | Q2 | Q3 | Q4 |
|--------|----|----|----|----|
| GitHub stars | 500 | 1,000 | 2,000 | 5,000 |
| Weekly active scans | 1,000 | 5,000 | 15,000 | 30,000 |
| Paying customers | 0 | 10 | 50 | 100 |
| MRR (Monthly Recurring Revenue) | $0 | $1K | $10K | $30K |

### Community KPIs
| Metric | Q1 | Q2 | Q3 | Q4 |
|--------|----|----|----|----|
| Contributors | 2 | 5 | 10 | 20 |
| Discord members | 0 | 50 | 200 | 500 |
| Blog post views | 1K | 5K | 15K | 30K |
| Conference talks | 0 | 1 | 2 | 3 |

---

## Risk Mitigation

### Technical Risks
**Risk:** Gitleaks integration complexity
- **Mitigation:** Prototype early, test with diverse artifacts
- **Contingency:** Maintain minimal custom detectors as fallback

**Risk:** Registry API rate limits
- **Mitigation:** Implement intelligent caching, batch requests
- **Contingency:** Offer pull-based scanning as alternative

**Risk:** Performance degradation with scale
- **Mitigation:** Load testing from day 1, horizontal scaling
- **Contingency:** Implement scan queuing system

### Business Risks
**Risk:** Gitleaks sees us as competitive threat
- **Mitigation:** Open communication, offer to contribute upstream
- **Contingency:** Emphasize complementary positioning

**Risk:** Market too niche
- **Mitigation:** Start with broad DevSecOps, narrow based on traction
- **Contingency:** Expand to general scanning if needed

**Risk:** Slow enterprise sales cycles
- **Mitigation:** Self-serve pricing, land-and-expand strategy
- **Contingency:** Focus on SMB/mid-market initially

---

## How We'll Know We're Succeeding

### 3 Months (End of Q1)
- ✅ Gitleaks integration shipped
- ✅ 500 GitHub stars
- ✅ 5+ Discord discussions per week
- ✅ 1 design partner actively testing

### 6 Months (End of Q2)
- ✅ 10 paying customers ($1K MRR)
- ✅ Featured in DevSecOps newsletter
- ✅ 1,000 GitHub stars
- ✅ Registry scanning adopted by design partners

### 9 Months (End of Q3)
- ✅ 50 paying customers ($10K MRR)
- ✅ SOC2 compliance (if hosted)
- ✅ 2,000 GitHub stars
- ✅ Speaking at regional security conference

### 12 Months (End of Q4)
- ✅ 100 paying customers ($30K MRR)
- ✅ 5,000 GitHub stars
- ✅ Profitable unit economics
- ✅ Series A funded OR profitable and bootstrapped

---

**Next Review:** End of Q1 2025
**Owner:** @franzer
**Stakeholders:** Engineering team, design partners, early customers
