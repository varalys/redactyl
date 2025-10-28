#!/usr/bin/env bash
set -euo pipefail

# Generate test fixtures with known secrets for integration testing

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES_DIR="$(cd "$SCRIPT_DIR/.." && pwd)/fixtures"

echo "Generating test fixtures in $FIXTURES_DIR"

# Create directory structure
mkdir -p "$FIXTURES_DIR"/{secrets,archives,containers,helm,k8s}

# =============================================================================
# Baseline Secrets
# =============================================================================

echo "Creating baseline secret fixtures..."

# Simple secret (high-entropy generic secret that Gitleaks will detect)
cat > "$FIXTURES_DIR/secrets/simple.txt" << 'EOF'
# Configuration file with embedded secret
# Using generic-api-key pattern with high entropy
export API_KEY="live_sk_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t"
export SECRET_TOKEN="ghp_1A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P7Q8R9S0T"
EOF

# Multiple secrets (high entropy patterns)
cat > "$FIXTURES_DIR/secrets/multiple.txt" << 'EOF'
# Multiple secret types with high entropy
github_token=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCd
slack_webhook=https://hooks.slack.com/services/T01ABC123/B02DEF456/XxYyZz0123456789AbCdEfGh
database_password=9KpL2mN3oP4qR5sT6uV7wX8yZ9aB0cD1eF2gH3iJ
api_secret=sk_live_AbC123DeF456GhI789JkL012MnO345PqR678StU901
EOF

# JSON with secrets (high entropy)
cat > "$FIXTURES_DIR/secrets/config.json" << 'EOF'
{
  "app": {
    "name": "test-app",
    "api_key": "sk_prod_1A2b3C4d5E6f7G8h9I0j1K2l3M4n5O6p7Q8r",
    "database": {
      "host": "localhost",
      "password": "Xy9Z8aB7cD6eF5gH4iJ3kL2mN1oP0qR9sT8uV7wX"
    }
  }
}
EOF

# YAML with secrets (high entropy)
cat > "$FIXTURES_DIR/secrets/config.yaml" << 'EOF'
app:
  name: test-app
  api_key: sk_test_9Z8y7X6w5V4u3T2s1R0q9P8o7N6m5L4k3J2i1H0g
  database:
    host: localhost
    password: aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3
EOF

# =============================================================================
# Archives
# =============================================================================

echo "Creating archive fixtures..."

# Create temp directory for archive contents
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Zip with secrets
mkdir -p "$TEMP_DIR/zip-content"
cat > "$TEMP_DIR/zip-content/credentials.txt" << 'EOF'
username=admin
password=SecretPassword123!
api_token=tok_1234567890abcdefghijklmnopqrst
EOF

(cd "$TEMP_DIR/zip-content" && zip -q "$FIXTURES_DIR/archives/secrets.zip" credentials.txt)

# Tar.gz with secrets
mkdir -p "$TEMP_DIR/tgz-content"
cat > "$TEMP_DIR/tgz-content/env.sh" << 'EOF'
export DATABASE_URL="postgresql://user:SecretPass123!@db.example.com:5432/prod"
export API_KEY="sk_live_1234567890abcdefghijklmnopqrstuvwxyz"
EOF

tar -czf "$FIXTURES_DIR/archives/secrets.tar.gz" -C "$TEMP_DIR/tgz-content" env.sh

# Nested archive (zip inside tar)
mkdir -p "$TEMP_DIR/nested"
cat > "$TEMP_DIR/nested/secret.txt" << 'EOF'
SECRET_TOKEN=ghp_SuperSecretGitHubToken1234567890abcdef
EOF

(cd "$TEMP_DIR/nested" && zip -q inner.zip secret.txt)
tar -cf "$FIXTURES_DIR/archives/nested.tar" -C "$TEMP_DIR/nested" inner.zip

# =============================================================================
# Helm Charts
# =============================================================================

echo "Creating Helm chart fixtures..."

# Create Helm chart directory
CHART_DIR="$FIXTURES_DIR/helm/test-chart"
mkdir -p "$CHART_DIR/templates"

# Chart.yaml
cat > "$CHART_DIR/Chart.yaml" << 'EOF'
apiVersion: v2
name: test-chart
description: Test Helm chart with secrets for integration testing
version: 1.0.0
appVersion: "1.0"
EOF

# values.yaml with secrets
cat > "$CHART_DIR/values.yaml" << 'EOF'
replicaCount: 1

image:
  repository: nginx
  tag: "1.21"

# WARNING: These are test secrets!
secrets:
  databasePassword: "SuperSecretDBPassword123!"
  apiKey: "sk_test_1234567890abcdefghijklmnopqrstuvwxyz"
  githubToken: "ghp_TestTokenForIntegrationTesting123456789"

service:
  type: ClusterIP
  port: 80
EOF

# Template with hardcoded secret (bad practice, but tests our detection)
cat > "$CHART_DIR/templates/secret.yaml" << 'EOF'
apiVersion: v1
kind: Secret
metadata:
  name: {{ .Chart.Name }}-secret
type: Opaque
stringData:
  # WARNING: Hardcoded secret for testing
  api-key: "sk_hardcoded_1234567890abcdefghijklmnopqrst"
  database-url: "postgresql://user:HardcodedPassword123!@db:5432/app"
EOF

# Deployment template
cat > "$CHART_DIR/templates/deployment.yaml" << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Chart.Name }}
spec:
  replicas: {{ .Values.replicaCount }}
  selector:
    matchLabels:
      app: {{ .Chart.Name }}
  template:
    metadata:
      labels:
        app: {{ .Chart.Name }}
    spec:
      containers:
      - name: {{ .Chart.Name }}
        image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
        env:
        - name: DATABASE_PASSWORD
          value: {{ .Values.secrets.databasePassword | quote }}
        - name: API_KEY
          value: {{ .Values.secrets.apiKey | quote }}
EOF

# Package Helm chart as .tgz
(cd "$FIXTURES_DIR/helm" && tar -czf test-chart.tgz test-chart/)

# =============================================================================
# Kubernetes Manifests
# =============================================================================

echo "Creating Kubernetes manifest fixtures..."

# Secret manifest
cat > "$FIXTURES_DIR/k8s/secret.yaml" << 'EOF'
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
  namespace: default
type: Opaque
stringData:
  database-password: "SecretDBPassword123!"
  api-key: "sk_prod_1234567890abcdefghijklmnopqrstuvwxyz"
  github-token: "ghp_ProductionToken1234567890abcdefghijk"
EOF

# Deployment with env secrets
cat > "$FIXTURES_DIR/k8s/deployment.yaml" << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
  namespace: default
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
    spec:
      containers:
      - name: myapp
        image: myapp:latest
        env:
        # BAD PRACTICE: Hardcoded secrets in env
        - name: DATABASE_PASSWORD
          value: "HardcodedDBPass123!"
        - name: API_TOKEN
          value: "tok_prod_1234567890abcdefghijklmnopqrstuvwxyz"
        - name: STRIPE_KEY
          value: "sk_live_1234567890abcdefghijklmnopqrstuvwxyzABCDEF"
EOF

# Multi-document YAML
cat > "$FIXTURES_DIR/k8s/multi-doc.yaml" << 'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  config.yaml: |
    api_url: https://api.example.com
    # WARNING: Secret in ConfigMap!
    admin_token: "tok_admin_1234567890abcdefghijklmnopqrst"
---
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
type: Opaque
stringData:
  username: admin
  password: "SuperSecretPassword123!"
  connection-string: "Server=db.example.com;Database=prod;User Id=admin;Password=SuperSecretPassword123!;"
EOF

# =============================================================================
# Summary
# =============================================================================

echo ""
echo "✅ Test fixtures generated successfully!"
echo ""
echo "Structure:"
find "$FIXTURES_DIR" -type f | sort | sed 's|^|  |'
echo ""
echo "⚠️  These fixtures contain FAKE secrets for testing purposes only!"
