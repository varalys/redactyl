#!/usr/bin/env bash
set -euo pipefail

# Download real-world artifacts for integration testing

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOWNLOADS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)/downloads"

echo "Downloading test artifacts to $DOWNLOADS_DIR"
mkdir -p "$DOWNLOADS_DIR"

# =============================================================================
# Container Images
# =============================================================================

echo ""
echo "=== Downloading Container Images ==="

# Download Alpine Linux (small, clean image for testing OCI format)
if command -v docker &> /dev/null; then
    echo "Pulling alpine:latest..."
    docker pull alpine:latest

    echo "Saving alpine:latest to $DOWNLOADS_DIR/alpine.tar..."
    docker save alpine:latest -o "$DOWNLOADS_DIR/alpine.tar"

    echo "✓ Alpine image saved ($(du -h "$DOWNLOADS_DIR/alpine.tar" | cut -f1))"
else
    echo "⚠️  Docker not found, skipping container downloads"
fi

# =============================================================================
# Helm Charts (from public registries)
# =============================================================================

echo ""
echo "=== Downloading Helm Charts ==="

if command -v helm &> /dev/null; then
    # Add stable repo
    helm repo add stable https://charts.helm.sh/stable || true
    helm repo update

    # Download a popular chart (nginx)
    echo "Downloading stable/nginx-ingress chart..."
    helm pull stable/nginx-ingress --destination "$DOWNLOADS_DIR" || \
        echo "⚠️  Failed to download nginx-ingress chart (may be deprecated)"

    # Download bitnami/mysql (if available)
    helm repo add bitnami https://charts.bitnami.com/bitnami || true
    helm repo update

    echo "Downloading bitnami/mysql chart..."
    helm pull bitnami/mysql --destination "$DOWNLOADS_DIR" || \
        echo "⚠️  Failed to download mysql chart"

    echo "✓ Helm charts downloaded"
else
    echo "⚠️  Helm not found, skipping Helm chart downloads"
fi

# =============================================================================
# Large Archives (for performance testing)
# =============================================================================

echo ""
echo "=== Creating Large Test Archives ==="

# Create a large archive with many files for performance testing
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

echo "Generating 1000 test files..."
mkdir -p "$TEMP_DIR/large-archive"
for i in {1..1000}; do
    # Create files with some containing secrets
    if [ $((i % 100)) -eq 0 ]; then
        echo "File $i with secret: API_KEY=sk_test_${i}_1234567890abcdefghijklmnopqrst" \
            > "$TEMP_DIR/large-archive/file_$i.txt"
    else
        echo "File $i with random content: $(head -c 100 /dev/urandom | base64)" \
            > "$TEMP_DIR/large-archive/file_$i.txt"
    fi
done

echo "Creating large archive..."
tar -czf "$DOWNLOADS_DIR/large-archive.tar.gz" -C "$TEMP_DIR" large-archive/
echo "✓ Large archive created ($(du -h "$DOWNLOADS_DIR/large-archive.tar.gz" | cut -f1))"

# =============================================================================
# Real-world Kubernetes Manifests
# =============================================================================

echo ""
echo "=== Downloading Kubernetes Manifests ==="

mkdir -p "$DOWNLOADS_DIR/k8s-examples"

# Download example manifests from Kubernetes docs
echo "Downloading example K8s manifests..."

# Example deployment
curl -sL https://raw.githubusercontent.com/kubernetes/website/main/content/en/examples/application/deployment.yaml \
    -o "$DOWNLOADS_DIR/k8s-examples/deployment.yaml" 2>/dev/null || \
    echo "⚠️  Failed to download K8s deployment example"

# Example service
curl -sL https://raw.githubusercontent.com/kubernetes/website/main/content/en/examples/service/networking/service.yaml \
    -o "$DOWNLOADS_DIR/k8s-examples/service.yaml" 2>/dev/null || \
    echo "⚠️  Failed to download K8s service example"

echo "✓ K8s manifests downloaded"

# =============================================================================
# Summary
# =============================================================================

echo ""
echo "=== Download Summary ==="
echo ""
echo "Downloaded artifacts:"
find "$DOWNLOADS_DIR" -type f -exec du -h {} \; | sort -k2
echo ""

# Create marker file
touch "$DOWNLOADS_DIR/.downloaded"

echo "✅ All artifacts downloaded successfully!"
echo ""
echo "Note: Run 'rm $DOWNLOADS_DIR/.downloaded' to force re-download on next run"
