#!/usr/bin/env bash
set -euo pipefail

# Redactyl Integration Demo
# Shows real-world secret detection across different artifact types

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
REDACTYL_BIN="${PROJECT_ROOT}/bin/redactyl"

echo -e "${BLUE}=== Redactyl Integration Demo ===${NC}"
echo "Demonstrating real-world secret detection"
echo ""

# Build if needed
if [ ! -f "$REDACTYL_BIN" ]; then
    echo -e "${YELLOW}Building Redactyl...${NC}"
    cd "$PROJECT_ROOT"
    make build
fi

# Generate fixtures if needed
if [ ! -d "$SCRIPT_DIR/fixtures" ]; then
    echo -e "${YELLOW}Generating test fixtures...${NC}"
    "$SCRIPT_DIR/scripts/generate-fixtures.sh"
fi

echo -e "${GREEN}✓ Setup complete${NC}"
echo ""

# Demo 1: Helm Chart Scanning
echo -e "${BLUE}=== Demo 1: Helm Chart Scanning ===${NC}"
echo "Scanning a Helm chart with secrets in values.yaml..."
echo ""
echo -e "${YELLOW}Command:${NC} redactyl scan --helm test/integration/fixtures/helm/"
echo ""
"$REDACTYL_BIN" scan --helm -p "$SCRIPT_DIR/fixtures/helm/" || true
echo ""

# Demo 2: Kubernetes Manifests
echo -e "${BLUE}=== Demo 2: Kubernetes Manifest Scanning ===${NC}"
echo "Scanning K8s manifests with hardcoded secrets..."
echo ""
echo -e "${YELLOW}Command:${NC} redactyl scan --k8s test/integration/fixtures/k8s/"
echo ""
"$REDACTYL_BIN" scan --k8s -p "$SCRIPT_DIR/fixtures/k8s/" || true
echo ""

# Demo 3: Archive Scanning
echo -e "${BLUE}=== Demo 3: Archive Scanning (No Disk Extraction) ===${NC}"
echo "Scanning secrets inside zip/tar archives without extracting..."
echo ""
echo -e "${YELLOW}Command:${NC} redactyl scan --archives test/integration/fixtures/archives/"
echo ""
"$REDACTYL_BIN" scan --archives -p "$SCRIPT_DIR/fixtures/archives/" || true
echo ""

# Demo 4: Combined Scanning
echo -e "${BLUE}=== Demo 4: Combined Cloud-Native Stack ===${NC}"
echo "Scanning everything together: Helm + K8s + Archives..."
echo ""
echo -e "${YELLOW}Command:${NC} redactyl scan --helm --k8s --archives test/integration/fixtures/"
echo ""
"$REDACTYL_BIN" scan --helm --k8s --archives -p "$SCRIPT_DIR/fixtures/" || true
echo ""

echo -e "${GREEN}=== Demo Complete! ===${NC}"
echo ""
echo "Key Features Demonstrated:"
echo "  • Helm chart scanning (.tgz and directories)"
echo "  • Kubernetes manifest detection"
echo "  • Archive streaming without disk extraction"
echo "  • Virtual paths showing artifact origins (::)"
echo "  • Gitleaks-powered detection"
