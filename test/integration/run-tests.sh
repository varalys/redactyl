#!/usr/bin/env bash
set -euo pipefail

# Redactyl Integration Test Runner
# Tests real-world scenarios with actual artifacts

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
REDACTYL_BIN="${PROJECT_ROOT}/bin/redactyl"
FIXTURES_DIR="${SCRIPT_DIR}/fixtures"
DOWNLOADS_DIR="${SCRIPT_DIR}/downloads"
RESULTS_DIR="${SCRIPT_DIR}/results"
VERBOSE="${VERBOSE:-0}"
SKIP_DOWNLOAD="${SKIP_DOWNLOAD:-0}"
TEST_CATEGORY="${1:-}"

# Setup
setup() {
    echo -e "${BLUE}=== Redactyl Integration Tests ===${NC}"
    echo "Project root: $PROJECT_ROOT"
    echo "Binary: $REDACTYL_BIN"
    echo ""

    mkdir -p "$DOWNLOADS_DIR" "$RESULTS_DIR"

    # Build binary if needed
    if [ ! -f "$REDACTYL_BIN" ]; then
        echo -e "${YELLOW}Building Redactyl binary...${NC}"
        cd "$PROJECT_ROOT"
        make build
    fi

    # Check Gitleaks
    if ! command -v gitleaks &> /dev/null; then
        echo -e "${RED}ERROR: Gitleaks not found in PATH${NC}"
        echo "Install: brew install gitleaks"
        exit 1
    fi

    # Generate fixtures
    if [ ! -d "$FIXTURES_DIR" ]; then
        echo -e "${YELLOW}Generating test fixtures...${NC}"
        "$SCRIPT_DIR/scripts/generate-fixtures.sh"
    fi

    # Download artifacts if needed
    if [ "$SKIP_DOWNLOAD" = "0" ] && [ ! -f "$DOWNLOADS_DIR/.downloaded" ]; then
        echo -e "${YELLOW}Downloading test artifacts...${NC}"
        "$SCRIPT_DIR/scripts/download-artifacts.sh"
    fi
}

# Run a test
run_test() {
    local name="$1"
    local category="$2"
    local min_expected="$3"
    local description="$4"
    shift 4

    # Skip if category filter doesn't match
    if [ -n "$TEST_CATEGORY" ] && [ "$TEST_CATEGORY" != "$category" ]; then
        return 0
    fi

    TESTS_RUN=$((TESTS_RUN + 1))

    echo -e "\n${BLUE}► Test: $name${NC}"
    echo "  Description: $description"
    [ "$VERBOSE" = "1" ] && echo "  Command: $*"

    local output_file="$RESULTS_DIR/${name//[^a-zA-Z0-9]/_}.json"

    # Run test (ignore exit code 1 which means findings were found)
    "$@" --json > "$output_file" 2>&1 || true

    # Check if output file exists and has valid JSON
    if [ ! -f "$output_file" ]; then
        echo -e "  ${RED}✗ FAIL${NC} - No output file generated"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi

    # Count findings
    local count=$(jq 'length' "$output_file" 2>/dev/null || echo "0")

    if [ "$count" -ge "$min_expected" ]; then
        echo -e "  ${GREEN}✓ PASS${NC} - Found ${GREEN}$count${NC} findings (expected >= $min_expected)"

        # Show sample findings if verbose
        if [ "$VERBOSE" = "1" ] && [ "$count" -gt 0 ]; then
            echo -e "  ${BLUE}Sample findings:${NC}"
            jq -r '.[:3] | .[] | "    • \(.detector): \(.path):\(.line)"' "$output_file" 2>/dev/null || true
        fi

        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "  ${RED}✗ FAIL${NC} - Expected >= $min_expected findings, got $count"
        [ "$VERBOSE" = "1" ] && jq -r '.[] | "    \(.detector): \(.path):\(.line)"' "$output_file" 2>/dev/null || true
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# =============================================================================
# Test Suites
# =============================================================================

test_baseline() {
    echo -e "\n${YELLOW}=== Baseline Tests ===${NC}"
    echo "Testing basic secret detection with Gitleaks (default mode - no flags required)"

    # Clear cache to ensure fresh scan
    rm -f "$FIXTURES_DIR/secrets/.redactylcache.json"

    run_test "baseline-default-scan" "baseline" 8 \
        "Scan regular files with default scanning (no flags)" \
        "$REDACTYL_BIN" scan -p "$FIXTURES_DIR/secrets/" --no-cache
}

test_helm() {
    echo -e "\n${YELLOW}=== Helm Tests ===${NC}"
    echo "Testing Helm chart scanning"

    run_test "helm-charts" "helm" 2 \
        "Scan Helm chart directory and .tgz" \
        "$REDACTYL_BIN" scan --helm -p "$FIXTURES_DIR/helm/"
}

test_k8s() {
    echo -e "\n${YELLOW}=== Kubernetes Tests ===${NC}"
    echo "Testing Kubernetes manifest scanning"

    run_test "k8s-manifests" "k8s" 1 \
        "Scan K8s Secret, Deployment, and multi-doc YAML" \
        "$REDACTYL_BIN" scan --k8s -p "$FIXTURES_DIR/k8s/"
}

test_archives() {
    echo -e "\n${YELLOW}=== Archive Tests ===${NC}"
    echo "Testing archive streaming without disk extraction"

    run_test "archives-streaming" "archives" 2 \
        "Scan zip, tar.gz, and nested archives" \
        "$REDACTYL_BIN" scan --archives -p "$FIXTURES_DIR/archives/"
}

test_containers() {
    echo -e "\n${YELLOW}=== Container Tests ===${NC}"
    echo "Testing Docker/OCI image scanning"

    if [ -f "$DOWNLOADS_DIR/alpine.tar" ]; then
        run_test "container-alpine" "containers" 0 \
            "Scan Alpine Linux image (should be clean)" \
            "$REDACTYL_BIN" scan --containers -p "$DOWNLOADS_DIR/"
        echo "  Note: Alpine should have 0 secrets (it's a clean base image)"
    else
        echo -e "  ${YELLOW}⊘ SKIP${NC} - Alpine image not downloaded"
    fi
}

test_combined() {
    echo -e "\n${YELLOW}=== Combined Tests ===${NC}"
    echo "Testing all artifact types together"

    run_test "combined-all-types" "combined" 6 \
        "Scan Helm + K8s + Archives + Files together" \
        "$REDACTYL_BIN" scan --helm --k8s --archives -p "$FIXTURES_DIR/"
}

test_performance() {
    echo -e "\n${YELLOW}=== Performance Tests ===${NC}"
    echo "Testing scan performance and time budgets"

    if [ -f "$DOWNLOADS_DIR/large-archive.tar.gz" ]; then
        local start_time=$(date +%s)

        run_test "perf-large-archive" "performance" 5 \
            "Scan large archive with time budget" \
            "$REDACTYL_BIN" scan --archives \
            --scan-time-budget 10s \
            --global-artifact-budget 30s \
            -p "$DOWNLOADS_DIR/"

        local end_time=$(date +%s)
        local duration=$((end_time - start_time))

        if [ "$duration" -gt 35 ]; then
            echo -e "  ${YELLOW}⚠ WARNING${NC}: Scan took ${duration}s (budget was 30s)"
        else
            echo -e "  ${GREEN}✓ Performance OK${NC}: Completed in ${duration}s"
        fi
    else
        echo -e "  ${YELLOW}⊘ SKIP${NC} - Large archive not generated"
    fi
}

test_virtual_paths() {
    echo -e "\n${YELLOW}=== Virtual Path Tests ===${NC}"
    echo "Testing virtual path preservation in nested artifacts"

    TESTS_RUN=$((TESTS_RUN + 1))

    # Run combined scan and check for :: in paths
    local output_file="$RESULTS_DIR/virtual_paths_test.json"
    "$REDACTYL_BIN" scan --helm --archives -p "$FIXTURES_DIR/" --json > "$output_file" 2>&1 || true

    if [ ! -f "$output_file" ]; then
        echo -e "  ${RED}✗ FAIL${NC} - No output file generated"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi

    local virtual_paths=$(jq -r '[.[] | select(.path | contains("::"))] | length' "$output_file" 2>/dev/null || echo "0")

    if [ "$virtual_paths" -gt 0 ]; then
        echo -e "  ${GREEN}✓ PASS${NC} - Found $virtual_paths findings with virtual paths (::)"
        if [ "$VERBOSE" = "1" ]; then
            echo -e "  ${BLUE}Example virtual paths:${NC}"
            jq -r '[.[] | select(.path | contains("::"))] | .[:3] | .[] | "    \(.path)"' "$output_file" 2>/dev/null || true
        fi
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "  ${RED}✗ FAIL${NC} - No virtual paths found in nested artifacts"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# =============================================================================
# Main
# =============================================================================

main() {
    setup

    # Run test suites based on category filter
    if [ -z "$TEST_CATEGORY" ] || [ "$TEST_CATEGORY" = "baseline" ]; then
        test_baseline
    fi

    if [ -z "$TEST_CATEGORY" ] || [ "$TEST_CATEGORY" = "helm" ]; then
        test_helm
    fi

    if [ -z "$TEST_CATEGORY" ] || [ "$TEST_CATEGORY" = "k8s" ]; then
        test_k8s
    fi

    if [ -z "$TEST_CATEGORY" ] || [ "$TEST_CATEGORY" = "archives" ]; then
        test_archives
    fi

    if [ -z "$TEST_CATEGORY" ] || [ "$TEST_CATEGORY" = "containers" ]; then
        test_containers
    fi

    if [ -z "$TEST_CATEGORY" ] || [ "$TEST_CATEGORY" = "combined" ]; then
        test_combined
    fi

    if [ -z "$TEST_CATEGORY" ] || [ "$TEST_CATEGORY" = "performance" ]; then
        test_performance
    fi

    if [ -z "$TEST_CATEGORY" ] || [ "$TEST_CATEGORY" = "virtual-paths" ]; then
        test_virtual_paths
    fi

    # Summary
    echo ""
    echo -e "${BLUE}=== Test Summary ===${NC}"
    echo -e "Tests run:     $TESTS_RUN"
    echo -e "${GREEN}Tests passed:  $TESTS_PASSED${NC}"
    if [ "$TESTS_FAILED" -gt 0 ]; then
        echo -e "${RED}Tests failed:  $TESTS_FAILED${NC}"
    else
        echo -e "Tests failed:  $TESTS_FAILED"
    fi
    echo ""

    if [ "$TESTS_FAILED" -gt 0 ]; then
        echo -e "${RED}❌ Some tests failed${NC}"
        echo "Run with VERBOSE=1 for details: VERBOSE=1 $0"
        exit 1
    else
        echo -e "${GREEN}✅ All tests passed!${NC}"
        exit 0
    fi
}

main "$@"
